from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field


class RegisterPayload(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    role: str
    first_name: str
    last_name: str
    birth_date: Optional[str] = None
    doctor_pin: Optional[str] = None
    phone_number: Optional[str] = None
    verification_code: Optional[str] = None


class LoginPayload(BaseModel):
    email: EmailStr
    password: str


class EmailCodePayload(BaseModel):
    email: EmailStr
    purpose: str = 'signup'


class CompleteOnboardingPayload(BaseModel):
    email: EmailStr
    verification_code: str = Field(min_length=4, max_length=8)
    new_password: str = Field(min_length=8)
    phone_number: str = Field(min_length=6)


class DoctorPinPayload(BaseModel):
    pin: str = Field(min_length=4, max_length=4)


class AppointmentPayload(BaseModel):
    date: str
    time: Optional[str] = ''
    title: str = Field(min_length=1)


class DossierUpdatePayload(BaseModel):
    blood_type: Optional[str] = None
    public_allergies: Optional[List[str]] = None
    public_conditions: Optional[List[str]] = None
    emergency_contact_name: Optional[str] = None
    emergency_contact_phone: Optional[str] = None
    emergency_instructions: Optional[str] = None
    private_data: Optional[Dict[str, Any]] = None


class CreatePatientPayload(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    first_name: str
    last_name: str
    birth_date: Optional[str] = None
    phone_number: Optional[str] = None
    blood_type: Optional[str] = None
    public_allergies: List[str] = []
    public_conditions: List[str] = []
    emergency_contact_name: Optional[str] = None
    emergency_contact_phone: Optional[str] = None
    emergency_instructions: Optional[str] = None
    private_data: Dict[str, Any] = {}


class ArrayItemPayload(BaseModel):
    value: str
