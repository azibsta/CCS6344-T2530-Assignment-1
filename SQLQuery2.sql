USE StudentProjectDB;
GO

-- 1. DROP the Security Policy FIRST (This unlocks the function)
IF EXISTS (SELECT * FROM sys.security_policies WHERE name = 'ProjectFilter')
    DROP SECURITY POLICY Sec.ProjectFilter;
GO

-- 2. DROP the Function NEXT
IF OBJECT_ID('Sec.fn_SecurityPredicate') IS NOT NULL
    DROP FUNCTION Sec.fn_SecurityPredicate;
GO

-- 3. Now Create the Function Fresh
CREATE FUNCTION Sec.fn_SecurityPredicate(@SubmittedBy INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_securitypredicate_result
WHERE 
    -- Admins(1), Lecturers(2), Examiners(4) see ALL
    CAST(SESSION_CONTEXT(N'RoleID') AS INT) IN (1, 2, 4)
    OR
    -- Students(3) see ONLY their own
    (CAST(SESSION_CONTEXT(N'RoleID') AS INT) = 3 AND @SubmittedBy = CAST(SESSION_CONTEXT(N'UserID') AS INT));
GO

-- 4. Create the Policy Again
CREATE SECURITY POLICY Sec.ProjectFilter
ADD FILTER PREDICATE Sec.fn_SecurityPredicate(SubmittedBy) ON App.Assignments,
ADD BLOCK PREDICATE Sec.fn_SecurityPredicate(SubmittedBy) ON App.Assignments 
WITH (STATE = ON);
GO