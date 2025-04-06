from fastapi import FastAPI, Depends, HTTPException,Query
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from user_models import User
from auth import hash_password, verify_password, create_access_token
from pydantic import BaseModel
from typing import Literal,Optional,List
from auth import get_current_user
from seat_schema import OccupySeatRequest,Seat
from checker_assignment import CheckerAssignment

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class RegisterUser(BaseModel):
    username: str
    email: str
    password: str
    role: Literal["student", "checker", "admin"]
    college:str

@app.get("/")
def show_message():
    return "Welcome"

@app.post("/register")
def register_user(user: RegisterUser, db: Session = Depends(get_db)):
    hashed_pw = hash_password(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_pw, role=user.role,college=user.college)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}

class LoginUser(BaseModel):
    username: str
    password: str

@app.post("/login")
def login_user(user: LoginUser, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token({"sub": db_user.username, "role": db_user.role})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")
def read_my_info(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
    }

#Code for occupying seat using QR
@app.post("/occupy-seat")
def occupy_seat(
    request: OccupySeatRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can occupy seats")

    try:
        college, bus_no, seat_no = request.qr_data.strip().split("-")
        bus_no = int(bus_no)
        seat_no = int(seat_no)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid QR code format")

    # Check if student's college matches QR code college
    if current_user.college.lower() != college.lower():
        raise HTTPException(status_code=403, detail="You can only occupy seats from your own college")

    # 🔒 Check if student has already occupied any seat
    already_occupied = db.query(Seat).filter_by(occupied_by_id=current_user.id).first()
    if already_occupied:
        raise HTTPException(status_code=409, detail=f"You have already occupied Seat {already_occupied.seat_no} on Bus {already_occupied.bus_no}")

    seat = db.query(Seat).filter_by(
        college=college,
        bus_no=bus_no,
        seat_no=seat_no
    ).first()

    if not seat:
        raise HTTPException(status_code=404, detail="Seat not found")

    if seat.occupied_by_id is not None or seat.status == "occupied":
        raise HTTPException(status_code=409, detail="Seat already occupied")

    # Occupy the seat
    seat.occupied_by_id = current_user.id
    seat.status = "occupied"
    db.commit()

    return {
        "message": f"Seat {seat_no} on Bus {bus_no} at {college} occupied successfully"
    }

#Unoccupy the occupied seat
@app.post("/unoccupy-seat")
def unoccupy_seat(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can unoccupy seats")

    # Find the seat occupied by the current user
    seat = db.query(Seat).filter_by(
        occupied_by_id=current_user.id,
        status="occupied"
    ).first()

    if not seat:
        raise HTTPException(status_code=404, detail="You don't have an occupied seat")

    # Free the seat
    seat.occupied_by_id = None
    seat.status = "not occupied"
    db.commit()

    return {
        "message": f"Seat {seat.seat_no} on Bus {seat.bus_no} at {seat.college} has been successfully unoccupied"
    }


#Get list of all checkers from same college as admin
@app.get("/admin/checkers", response_model=List[dict])
def list_checkers_from_college(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can view checkers")

    checkers = db.query(User).filter_by(role="checker", college=current_user.college).all()
    return [{"id": checker.id, "username": checker.username, "email": checker.email} for checker in checkers]

#Assign checkers 
class AssignCheckerRequest(BaseModel):
    checker_id: int
    bus_no: int

@app.post("/admin/assign_checker")
def assign_checker(
    request: AssignCheckerRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can assign checkers")

    checker = db.query(User).filter_by(id=request.checker_id).first()

    if not checker or checker.role != "checker":
        raise HTTPException(status_code=404, detail="Invalid checker")

    if checker.college != current_user.college:
        raise HTTPException(status_code=403, detail="Checker must be from your college")

    existing_assignment = db.query(CheckerAssignment).filter_by(
        college=current_user.college,
        bus_no=request.bus_no
    ).first()

    if existing_assignment:
        # Update the checker
        existing_assignment.checker_id = request.checker_id
        message = f"Checker for Bus {request.bus_no} updated to {checker.username}"
    else:
        # Create a new assignment
        assignment = CheckerAssignment(
            checker_id=request.checker_id,
            college=current_user.college,
            bus_no=request.bus_no
        )
        db.add(assignment)
        message = f"Checker {checker.username} assigned to Bus {request.bus_no}"

    db.commit()

    return {"message": message}

#admins and checkers can see seat occupancy of the assigned buses
@app.get("/seat_occupancy")
def get_seat_occupancy(
    bus_no: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role == "checker":
        # Checker sees all buses assigned to them
        assignments = db.query(CheckerAssignment).filter_by(checker_id=current_user.id).all()

        if not assignments:
            raise HTTPException(status_code=404, detail="No assigned buses found")

        results = []

        for assignment in assignments:
            seats = db.query(Seat).filter_by(
                college=assignment.college,
                bus_no=assignment.bus_no
            ).all()

            seat_data = [
                {
                    "seat_no": seat.seat_no,
                    "status": seat.status,
                    "occupied_by_id": seat.occupied_by_id
                }
                for seat in seats
            ]

            results.append({
                "college": assignment.college,
                "bus_no": assignment.bus_no,
                "seats": seat_data
            })

        return results

    elif current_user.role == "admin":
        if not bus_no:
            raise HTTPException(status_code=400, detail="Bus number is required")

        seats = db.query(Seat).filter_by(
            college=current_user.college,
            bus_no=bus_no
        ).all()

        if not seats:
            raise HTTPException(status_code=404, detail="No seats found for this bus")

        return {
            "college": current_user.college,
            "bus_no": bus_no,
            "seats": [
                {
                    "seat_no": seat.seat_no,
                    "status": seat.status,
                    "occupied_by_id": seat.occupied_by_id
                }
                for seat in seats
            ]
        }

    else:
        raise HTTPException(status_code=403, detail="Only checkers and admins can view seat occupancy")
    
#Resetting all seats to not-occupied    
@app.post("/reset_seat_occupancy")
def reset_seat_occupancy(
    bus_no: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "checker":
        raise HTTPException(status_code=403, detail="Only checkers can reset seat occupancy")

    # Check if checker is assigned to this bus
    assignment = db.query(CheckerAssignment).filter_by(
        checker_id=current_user.id,
        bus_no=bus_no
    ).first()

    if not assignment:
        raise HTTPException(status_code=403, detail="You are not assigned to this bus")

    # Reset seat occupancy
    seats = db.query(Seat).filter_by(
        college=assignment.college,
        bus_no=bus_no
    ).all()

    if not seats:
        raise HTTPException(status_code=404, detail="No seats found for this bus")

    for seat in seats:
        seat.status = "not occupied"
        seat.occupied_by_id = None

    db.commit()

    return {"message": f"Seat occupancy for Bus {bus_no} has been reset"}

#Can't find the seat option
class CantFindSeatRequest(BaseModel):
    bus_no: int

@app.post("/cant-find-seat")
def cant_find_seat(
    request: CantFindSeatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can use this option")

    # Check if student already has an occupied seat
    existing_seat = db.query(Seat).filter_by(
        occupied_by_id=current_user.id,
        status="occupied"
    ).first()

    if existing_seat:
        raise HTTPException(status_code=400, detail="You have already occupied a seat")

    # Find checker assigned to this bus in student's college
    assignment = db.query(CheckerAssignment).filter_by(
        college=current_user.college,
        bus_no=request.bus_no
    ).first()

    if not assignment:
        raise HTTPException(status_code=404, detail="No checker assigned to this bus")

    checker = db.query(User).filter_by(id=assignment.checker_id).first()
    if not checker:
        raise HTTPException(status_code=404, detail="Checker not found")

    # Simulated notification
    print(f"🚨 Notification: Student '{current_user.username}' from '{current_user.college}' reported no available seat on Bus {request.bus_no}. Notify Checker '{checker.username}'.")

    return {
        "message": f"Checker '{checker.username}' has been notified about the issue on Bus {request.bus_no}"
    }




