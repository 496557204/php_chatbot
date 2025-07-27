const { createApp, ref, reactive, onMounted } = Vue;
const { ElMessage } = ElementPlus;

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', component: { template: '#dashboard-template' } },
  { path: '/encrypt', component: { template: '#encrypt-template' } },
  { path: '/permissions', component: { template: '#permissions-template' } }
];

const router = VueRouter.createRouter({
  history: VueRouter.createWebHashHistory(),
  routes
});

const app = createApp({
  setup() {
    const isAuthenticated = ref(false);
    const currentUser = reactive({ username: '', role: '' });
    const activeMenu = ref('dashboard');
    const loginForm = reactive({ username: '', password: '' });
    const permissions = ref([]);

    // 登录表单验证规则
    const loginRules = reactive({
      username: [
        { required: true, message: '请输入用户名', trigger: 'blur' }
      ],
      password: [
        { required: true, message: '请输入密码', trigger: 'blur' }
      ]
    });

    // 加密数据表单
    const encryptForm = reactive({
      plainText: '',
      encryptedText: ''
    });

    // 解密数据表单
    const decryptForm = reactive({
      encryptedText: '',
      decryptedText: ''
    });

    // 权限分配表单
    const permissionForm = reactive({
      username: '',
      resource: '',
      action: 'read'
    });

    // 检查权限
    const hasPermission = (resource, action) => {
      if (currentUser.role === 'admin') return true;
      return permissions.value.some(p =>
        p.resource === resource && p.action === action
      );
    };

    // 登录
    const handleLogin = async () => {
      try {
        const response = await axios.post('/token',
          `username=${loginForm.username}&password=${loginForm.password}`,
          {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
          }
        );

        localStorage.setItem('access_token', response.data.access_token);

        // 解析JWT获取用户信息
        const tokenData = JSON.parse(atob(response.data.access_token.split('.')[1]));
        currentUser.username = tokenData.sub;
        currentUser.role = tokenData.role;
        isAuthenticated.value = true;

        // 获取用户权限
        await fetchPermissions();

        // 跳转到仪表盘
        router.push('/dashboard');
      } catch (error) {
        ElMessage.error('登录失败: ' + (error.response?.data?.detail || '用户名或密码错误'));
      }
    };

    // 获取用户权限
    const fetchPermissions = async () => {
      try {
        const response = await axios.get('/permissions', {
          params: { username: currentUser.username },
          headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
        });
        permissions.value = response.data;
      } catch (error) {
        console.error('获取权限失败:', error);
      }
    };

    // 退出登录
    const handleLogout = () => {
      localStorage.removeItem('access_token');
      isAuthenticated.value = false;
      currentUser.username = '';
      currentUser.role = '';
      permissions.value = [];
      router.push('/');
    };

    // 加密数据
    const encryptData = async () => {
      if (!encryptForm.plainText) {
        ElMessage.warning('请输入要加密的文本');
        return;
      }

      try {
        const response = await axios.post('/encrypt',
          { data: encryptForm.plainText },
          { headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` } }
        );
        encryptForm.encryptedText = response.data.encrypted_data;
      } catch (error) {
        ElMessage.error('加密失败: ' + (error.response?.data?.detail || '服务器错误'));
      }
    };

    // 解密数据
    const decryptData = async () => {
      if (!decryptForm.encryptedText) {
        ElMessage.warning('请输入要解密的文本');
        return;
      }

      try {
        const response = await axios.post('/decrypt',
          { data: decryptForm.encryptedText },
          { headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` } }
        );
        decryptForm.decryptedText = response.data.decrypted_data;
      } catch (error) {
        ElMessage.error('解密失败: ' + (error.response?.data?.detail || '无效的加密文本'));
      }
    };

    // 分配权限
    const assignPermission = async () => {
      if (!permissionForm.username || !permissionForm.resource) {
        ElMessage.warning('请填写完整的权限信息');
        return;
      }

      try {
        await axios.post('/permissions',
          {
            username: permissionForm.username,
            resource: permissionForm.resource,
            action: permissionForm.action
          },
          { headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` } }
        );

        ElMessage.success('权限分配成功');
        permissionForm.username = '';
        permissionForm.resource = '';
        permissionForm.action = 'read';
      } catch (error) {
        ElMessage.error('权限分配失败: ' + (error.response?.data?.detail || '服务器错误'));
      }
    };

    // 初始化检查登录状态
    onMounted(() => {
      const token = localStorage.getItem('access_token');
      if (token) {
        try {
          const tokenData = JSON.parse(atob(token.split('.')[1]));
          currentUser.username = tokenData.sub;
          currentUser.role = tokenData.role;
          isAuthenticated.value = true;
          fetchPermissions();
        } catch (e) {
          localStorage.removeItem('access_token');
        }
      }
    });

    return {
      isAuthenticated,
      currentUser,
      activeMenu,
      loginForm,
      loginRules,
      encryptForm,
      decryptForm,
      permissionForm,
      hasPermission,
      handleLogin,
      handleLogout,
      encryptData,
      decryptData,
      assignPermission
    };
  }
});

app.use(ElementPlus);
app.use(router);
app.mount('#app');

// 定义模板
const templateContainer = document.createElement('div');
templateContainer.style.display = 'none';
templateContainer.innerHTML = `
  <!-- 仪表盘模板 -->
  <template id="dashboard-template">
    <div class="dashboard-container">
      <div class="dashboard-card">
        <h3 class="card-title">系统概览</h3>
        <p>欢迎使用安全管理系统，当前用户: {{ currentUser.username }}</p>
        <p>角色: {{ currentUser.role }}</p>
        <p>权限数量: {{ permissions.length }}</p>
      </div>
      <div class="dashboard-card">
        <h3 class="card-title">安全提示</h3>
        <p>• 请定期更改密码</p>
        <p>• 不要分享您的登录凭证</p>
        <p>• 敏感数据请使用加密功能</p>
      </div>
    </div>
  </template>
  
  <!-- 加密模板 -->
  <template id="encrypt-template">
    <div class="encrypt-container">
      <h3>数据加密</h3>
      <div class="encrypt-form">
        <el-input
          v-model="encryptForm.plainText"
          type="textarea"
          :rows="4"
          placeholder="请输入要加密的文本"
        ></el-input>
        <el-button type="primary" @click="encryptData" style="margin-top: 15px;">加密</el-button>
        
        <el-input
          v-model="encryptForm.encryptedText"
          type="textarea"
          :rows="4"
          placeholder="加密结果将显示在这里"
          readonly
          style="margin-top: 20px;"
        ></el-input>
      </div>
      
      <h3 style="margin-top: 30px;">数据解密</h3>
      <div class="encrypt-form">
        <el-input
          v-model="decryptForm.encryptedText"
          type="textarea"
          :rows="4"
          placeholder="请输入要解密的文本"
        ></el-input>
        <el-button type="primary" @click="decryptData" style="margin-top: 15px;">解密</el-button>
        
        <el-input
          v-model="decryptForm.decryptedText"
          type="textarea"
          :rows="4"
          placeholder="解密结果将显示在这里"
          readonly
          style="margin-top: 20px;"
        ></el-input>
      </div>
    </div>
  </template>
  
  <!-- 权限管理模板 -->
  <template id="permissions-template">
    <div class="permissions-container">
      <h3>权限分配</h3>
      <div class="permission-form">
        <el-form :model="permissionForm" label-width="80px">
          <el-form-item label="用户名">
            <el-input v-model="permissionForm.username" placeholder="输入要分配权限的用户名"></el-input>
          </el-form-item>
          <el-form-item label="资源">
            <el-input v-model="permissionForm.resource" placeholder="输入资源名称（如data）"></el-input>
          </el-form-item>
          <el-form-item label="操作">
            <el-select v-model="permissionForm.action" placeholder="选择操作">
              <el-option label="读取" value="read"></el-option>
              <el-option label="写入" value="write"></el-option>
              <el-option label="删除" value="delete"></el-option>
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="assignPermission">分配权限</el-button>
          </el-form-item>
        </el-form>
      </div>
      
      <h3 style="margin-top: 30px;">当前用户权限</h3>
      <el-table :data="permissions" class="permission-table">
        <el-table-column prop="resource" label="资源"></el-table-column>
        <el-table-column prop="action" label="操作"></el-table-column>
      </el-table>
    </div>
  </template>
`;
document.body.appendChild(templateContainer);
