USE StudentProjectDB;
GO

IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'Sec') EXEC('CREATE SCHEMA Sec');
GO

CREATE OR ALTER FUNCTION Sec.fn_SecurityPredicate(@SubmittedBy INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_securitypredicate_result
WHERE 
    CAST(SESSION_CONTEXT(N'RoleID') AS INT) IN (1, 2, 4)
    OR
    (CAST(SESSION_CONTEXT(N'RoleID') AS INT) = 3 AND @SubmittedBy = CAST(SESSION_CONTEXT(N'UserID') AS INT));
GO

CREATE SECURITY POLICY Sec.ProjectFilter
ADD FILTER PREDICATE Sec.fn_SecurityPredicate(SubmittedBy) ON App.Assignments,
ADD BLOCK PREDICATE Sec.fn_SecurityPredicate(SubmittedBy) ON App.Assignments 
WITH (STATE = ON);
GO