-- 智能安全管理系统数据库结构
-- 数据库名称: ohvbkqek

-- 创建角色表
CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建用户表
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255),
    role_id INT NOT NULL,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- 创建权限表
CREATE TABLE IF NOT EXISTS permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE KEY unique_permission (user_id, resource, action)
);

-- 创建菜单项表
CREATE TABLE IF NOT EXISTS menu_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    path VARCHAR(100) NOT NULL,
    icon VARCHAR(50),
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建聊天会话表
CREATE TABLE IF NOT EXISTS chat_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 创建聊天消息表
CREATE TABLE IF NOT EXISTS chat_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id INT NOT NULL,
    role ENUM('user', 'assistant') NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES chat_sessions(id)
);

-- 初始化角色数据
INSERT INTO roles (name, description) VALUES
('admin', '系统管理员，拥有所有权限'),
('user', '普通用户，拥有基本权限'),
('guest', '访客用户，拥有只读权限');

-- 初始化菜单项数据
INSERT INTO menu_items (name, path, icon, sort_order) VALUES
('仪表盘', 'dashboard', 'el-icon-menu', 1),
('数据加密', 'encrypt', 'el-icon-lock', 2),
('权限管理', 'permissions', 'el-icon-setting', 3),
('AI助手', 'chat', 'el-icon-chat-dot-round', 4);

-- 初始化管理员用户
-- 密码: admin123
INSERT INTO users (username, password_hash, role_id) VALUES
('admin', '$2b$12$KIXxPfnK3f8v8v8v8v8v8u8v8v8v8v8v8v8v8v8v8v8v8v8v8v8v8v', 1);

-- 初始化普通用户
-- 密码: user123
INSERT INTO users (username, password_hash, role_id) VALUES
('user', '$2b$12$KIXxPfnK3f8v8v8v8v8v8u8v8v8v8v8v8v8v8v8v8v8v8v8v8v8v8v', 2);

-- 初始化访客用户
-- 密码: guest123
INSERT INTO users (username, password_hash, role_id) VALUES
('guest', '$2b$12$KIXxPfnK3f8v8v8v8v8v8u8v8v8v8v8v8v8v8v8v8v8v8v8v8v8v8v', 3);

-- 为管理员分配所有权限
INSERT INTO permissions (user_id, resource, action) VALUES
(1, 'data', 'read'),
(1, 'data', 'write'),
(1, 'data', 'delete'),
(1, 'permission', 'read'),
(1, 'permission', 'write'),
(1, 'permission', 'delete'),
(1, 'system', 'read'),
(1, 'system', 'write'),
(1, 'system', 'delete');

-- 为普通用户分配基本权限
INSERT INTO permissions (user_id, resource, action) VALUES
(2, 'data', 'read'),
(2, 'data', 'write'),
(2, 'system', 'read');

-- 为访客用户分配只读权限
INSERT INTO permissions (user_id, resource, action) VALUES
(3, 'data', 'read'),
(3, 'system', 'read');

-- 常用查询语句

-- 查询用户及其角色信息
SELECT u.id, u.username, r.name as role, r.description, u.last_login, u.created_at
FROM users u
JOIN roles r ON u.role_id = r.id;

-- 查询用户权限
SELECT u.username, p.resource, p.action
FROM users u
JOIN permissions p ON u.id = p.user_id
ORDER BY u.username, p.resource, p.action;

-- 查询用户菜单权限
SELECT u.username, m.name, m.path, m.icon
FROM users u
JOIN roles r ON u.role_id = r.id
JOIN permissions p ON u.id = p.user_id
JOIN menu_items m ON m.path LIKE CONCAT('%', p.resource, '%')
WHERE p.action = 'read'
ORDER BY u.username, m.sort_order;

-- 查询用户的聊天会话
SELECT s.id, s.title, s.created_at, s.updated_at, u.username
FROM chat_sessions s
JOIN users u ON s.user_id = u.id
WHERE u.username = 'admin'
ORDER BY s.updated_at DESC;

-- 查询聊天消息
SELECT m.id, m.session_id, m.role, m.content, m.created_at, s.title
FROM chat_messages m
JOIN chat_sessions s ON m.session_id = s.id
WHERE s.user_id = 1
ORDER BY m.created_at;

-- 更新用户最后登录时间
UPDATE users SET last_login = NOW() WHERE username = 'admin';

-- 查询系统统计信息
SELECT
    (SELECT COUNT(*) FROM users) as total_users,
    (SELECT COUNT(*) FROM roles) as total_roles,
    (SELECT COUNT(*) FROM permissions) as total_permissions,
    (SELECT COUNT(*) FROM chat_sessions) as total_sessions,
    (SELECT COUNT(*) FROM chat_messages) as total_messages;

-- 创建索引优化查询性能
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_permissions_user_resource ON permissions(user_id, resource);
CREATE INDEX idx_chat_sessions_user ON chat_sessions(user_id);
CREATE INDEX idx_chat_messages_session ON chat_messages(session_id);
CREATE INDEX idx_chat_messages_created ON chat_messages(created_at);
