# Secure CareFlow Operation Scheduler Security Specifications

## 1. Data Invariants
1. **Immutable User Role Bounds:** Users can never upgrade their own `role` field from `user` to `admin` without authorization.
2. **Doctor & Patient Records:** Modification (create, update, delete) requires `admin` role privileges. Reading is authorized for all signed-in medical staff (both admins and regular users).
3. **Operation Schedule:** Surgery schedules require strict admin management. All scheduled entries require essential medical variables (OT ID, Anesthesia type, surgeon names, and patient IDs).
4. **Audit Immutability:** Activity log entries (`activityLogs`) are strictly write-once. They cannot be modified or deleted.
5. **Verified Auth Presence:** Only successfully authenticated hospital personnel are permitted to access any records.

---

## 2. The "Dirty Dozen" Payloads

These are malicious JSON payloads that the Firebase Security Rules mathematically reject:

### P1: Self-Admin Upgrade Post-Registration
Attempt to modify own User profile to escalate permissions to `admin`.
```json
{
  "uid": "USER123",
  "email": "malicious@hospital.com",
  "role": "admin"
}
```
*Expected: PERMISSION_DENIED (unless verified as admin)*

### P2: Anonymous Resource Scraping
Attempting to read the schedule database without authenticating (null auth token).
*Expected: PERMISSION_DENIED*

### P3: Doctor Account Spoofing (Write access by regular User)
User attempts to create a Doctor document containing custom credentials and active status.
```json
{
  "id": "doc_hack",
  "name": "Hacker MD",
  "specialty": "Cardiology",
  "department": "Surgery",
  "status": "active"
}
```
*Expected: PERMISSION_DENIED*

### P4: Doctor Account Spoofing (Anonymously)
Anonymous client attempts to create a Doctor document.
*Expected: PERMISSION_DENIED*

### P5: Invalid Doc ID Injection (Buffer overflow attempt)
Attempting to lock the databases with a high-byte document key payload.
*Document ID: "abcde_super_long_junk_string_with_excessive_payloads_1234567890_..." (size > 128 chars)*
*Expected: PERMISSION_DENIED*

### P6: Patient File Injection by Non-Admin
A regular user trying to register or modify a private Patient record.
```json
{
  "id": "pat_99",
  "name": "Jane Eyre",
  "age": 45,
  "gender": "Female",
  "bloodType": "A+",
  "phone": "555-0192"
}
```
*Expected: PERMISSION_DENIED*

### P7: Surgery Schedule Modification by a User
Regular user trying to change the scheduled date/time of a surgery to create chaos.
```json
{
  "id": "sched_1",
  "dateTime": "2026-05-20T09:00:00Z"
}
```
*Expected: PERMISSION_DENIED*

### P8: Deleting Historical Activity Logs (Covering tracks)
Attempt to call `delete()` on `activityLogs/log_007`.
*Expected: PERMISSION_DENIED*

### P9: Arbitrary field spoofing in Activity Log
Writing an Activity Log for another user's UID to frame someone else.
```json
{
  "id": "log_99",
  "timestamp": "2026-05-19T20:00:00Z",
  "action": "Deleted Database",
  "userId": "SOMEONE_ELSE_UID",
  "userEmail": "victim@hospital.com",
  "details": "Deleted all surgery records"
}
```
*Expected: PERMISSION_DENIED (userId doesn't match request.auth.uid)*

### P10: Modifying Historical Activity Logs (Updating entry)
Attempting to edit details of an existing log to erase trace of an action.
```json
{
  "details": "No issues found"
}
```
*Expected: PERMISSION_DENIED*

### P11: Creating a Schedule referencing Non-existent Doctor
Creating a surgery schedule when referencing a surgeon listing that has not been approved.
*Expected: Verified at app level through Firestore queries before scheduling.*

### P12: Overwriting someone else's User profile
User tries to write `users/victim_user_id` with their own email.
```json
{
  "uid": "victim_user_id",
  "email": "malicious@hospital.com",
  "role": "user"
}
```
*Expected: PERMISSION_DENIED (uid does not match request.auth.uid)*

---

## 3. The Test Runner
The security design is validated through Firestore local rule simulators and is verified in code prior to writing any database queries to guarantee strict adherence.
