USE master;
GO
IF EXISTS (SELECT * FROM sys.databases WHERE name = 'StudentProjectDB')
    DROP DATABASE StudentProjectDB;
GO
CREATE DATABASE StudentProjectDB;
GO
USE StudentProjectDB;
GO

-- --- SCHEMAS (Lecture 3: Security Layering) ---
GO
CREATE SCHEMA App; -- For Application Data
GO
CREATE SCHEMA Sec; -- For Security configurations and logs
GO

-- --- TABLES ---

-- 1. Roles (4 Mandatory Roles)
CREATE TABLE App.Roles (
    RoleID INT PRIMARY KEY IDENTITY(1,1),
    RoleName NVARCHAR(50) UNIQUE NOT NULL
);

-- 2. Users (With Column Encryption & Masking - Lecture 3)
CREATE TABLE App.Users (
    UserID INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(256) NOT NULL,
    Salt NVARCHAR(50) NOT NULL,
    
    -- Dynamic Data Masking (Hides email from unauthorized queries)
    Email NVARCHAR(100) MASKED WITH (FUNCTION = 'email()') NULL,
    
    -- Encrypted Column (Stores binary garbage, readable only via key)
    EncryptedPhone VARBINARY(MAX) NULL, 
    
    RoleID INT FOREIGN KEY REFERENCES App.Roles(RoleID),
    PDPA_Consent BIT DEFAULT 0, -- Lecture 1: Compliance
    CreatedAt DATETIME DEFAULT GETDATE()
);

-- 3. Assignments (Main Data)
CREATE TABLE App.Assignments (
    AssignmentID INT PRIMARY KEY IDENTITY(1,1),
    ProjectTitle NVARCHAR(100),
    Description NVARCHAR(255),
    GitHubLink NVARCHAR(200),
    SubmittedBy INT FOREIGN KEY REFERENCES App.Users(UserID),
    SubmissionDate DATETIME DEFAULT GETDATE()
);

-- 4. Milestones (Feature: Goals)
CREATE TABLE App.Milestones (
    MilestoneID INT PRIMARY KEY IDENTITY(1,1),
    AssignmentID INT FOREIGN KEY REFERENCES App.Assignments(AssignmentID) ON DELETE CASCADE,
    TaskName NVARCHAR(100),
    IsCompleted BIT DEFAULT 0
);

-- 5. Notifications (Feature: Alerts)
CREATE TABLE App.Notifications (
    NotifID INT PRIMARY KEY IDENTITY(1,1),
    UserID INT FOREIGN KEY REFERENCES App.Users(UserID),
    Message NVARCHAR(255),
    IsRead BIT DEFAULT 0,
    DateCreated DATETIME DEFAULT GETDATE()
);

-- 6. Feedback (Feature: Reporting)
CREATE TABLE App.Feedback (
    FeedbackID INT PRIMARY KEY IDENTITY(1,1),
    SubmittedBy INT FOREIGN KEY REFERENCES App.Users(UserID),
    IssueType NVARCHAR(50),
    Message NVARCHAR(MAX),
    DateCreated DATETIME DEFAULT GETDATE()
);

-- 7. Audit Log (Lecture 2: Security Audit)
CREATE TABLE Sec.AuditLog (
    AuditID INT PRIMARY KEY IDENTITY(1,1),
    ActionType NVARCHAR(50), 
    TableName NVARCHAR(50),
    RecordID INT,
    UserIP NVARCHAR(50),
    Timestamp DATETIME DEFAULT GETDATE(),
    Details NVARCHAR(255)
);

-- 8. System Config (Lecture 6: Reducing Attack Surface)
CREATE TABLE Sec.SystemConfig (
    ConfigKey NVARCHAR(50) PRIMARY KEY,
    ConfigValue NVARCHAR(50) -- 'TRUE' or 'FALSE'
);

-- --- SEED DATA ---
INSERT INTO App.Roles (RoleName) VALUES 
('Admin'),            -- Role 1
('Lecturer'),         -- Role 2
('Student'),          -- Role 3
('External Examiner');-- Role 4

INSERT INTO Sec.SystemConfig VALUES ('AllowUploads', 'TRUE');

-- --- TRIGGERS (Lecture 2: Automated Auditing) ---
GO
CREATE TRIGGER trg_AuditAssignments
ON App.Assignments
AFTER INSERT, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    -- Log Inserts
    IF EXISTS (SELECT * FROM inserted)
    BEGIN
        INSERT INTO Sec.AuditLog (ActionType, TableName, RecordID, Details)
        SELECT 'INSERT_PROJECT', 'Assignments', AssignmentID, ProjectTitle FROM inserted;
        
        -- Auto-Notify Lecturers (Role 2)
        INSERT INTO App.Notifications (UserID, Message)
        SELECT UserID, 'New project submitted!' FROM App.Users WHERE RoleID = 2;
    END

    -- Log Deletes
    IF EXISTS (SELECT * FROM deleted)
        INSERT INTO Sec.AuditLog (ActionType, TableName, RecordID, Details)
        SELECT 'DELETE_PROJECT', 'Assignments', AssignmentID, ProjectTitle FROM deleted;
END
GO

-- --- STORED PROCEDURES (Lecture 3 & 5: Encryption & Injection Prevention) ---
GO
CREATE PROCEDURE Sec.sp_RegisterUser
    @Username NVARCHAR(50), 
    @PassHash NVARCHAR(256), 
    @Salt NVARCHAR(50), 
    @Email NVARCHAR(100),
    @Phone NVARCHAR(20),
    @RoleID INT
AS
BEGIN
    -- Encrypts Phone using a PassPhrase before storing
    INSERT INTO App.Users (Username, PasswordHash, Salt, Email, EncryptedPhone, RoleID, PDPA_Consent)
    VALUES (@Username, @PassHash, @Salt, @Email, 
            EncryptByPassPhrase('MySecureKey123', @Phone), 
            @RoleID, 1);
END
GO

CREATE PROCEDURE Sec.sp_GetDecryptedUser
    @Username NVARCHAR(50)
AS
BEGIN
    -- Decrypts phone number on-the-fly for Login verification
    SELECT UserID, PasswordHash, Salt, RoleID, Email, Username,
    CONVERT(NVARCHAR(50), DecryptByPassPhrase('MySecureKey123', EncryptedPhone)) as Phone
    FROM App.Users WHERE Username = @Username;
END
GO