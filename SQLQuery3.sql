USE StudentProjectDB;
GO

-- 1. Create a Schema for Security Logic if not exists
IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'Sec') EXEC('CREATE SCHEMA Sec');
GO

-- 2. Create a User mapping table to link SQL Login to App User (Simulated for this assignment)
-- In a real web app, we use SESSION_CONTEXT. We will simulate setting this context.

-- 3. The Security Predicate Function
-- This function returns 1 (Access Granted) or 0 (Access Denied) for a row
CREATE OR ALTER FUNCTION Sec.fn_SecurityPredicate(@SubmittedBy INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_securitypredicate_result
WHERE 
    -- Rule 1: Admins (Role 1), Lecturers (2), Examiners (4) can see everything
    CAST(SESSION_CONTEXT(N'RoleID') AS INT) IN (1, 2, 4)
    OR
    -- Rule 2: Students (Role 3) can ONLY see their own rows
    (CAST(SESSION_CONTEXT(N'RoleID') AS INT) = 3 AND @SubmittedBy = CAST(SESSION_CONTEXT(N'UserID') AS INT));
GO

-- 4. Apply the Policy to the Assignments Table
CREATE SECURITY POLICY Sec.ProjectFilter
ADD FILTER PREDICATE Sec.fn_SecurityPredicate(SubmittedBy) ON App.Assignments,
ADD BLOCK PREDICATE Sec.fn_SecurityPredicate(SubmittedBy) ON App.Assignments -- Prevents inserting for others
WITH (STATE = ON);
GO