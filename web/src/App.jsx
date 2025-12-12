import React, { useEffect, useState } from 'react';
import { Layout, Table, Button, Modal, Form, Input, Space, message, Tabs, Card, Descriptions, Select, Tag, Divider, Tooltip, Row, Col, Statistic } from 'antd';
import { api } from './api';

const { Header, Content } = Layout;

const formatBytes = (n=0) => {
  if (!n) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  let idx = 0, val = n;
  while (val >= 1024 && idx < units.length-1) { val/=1024; idx++; }
  return `${val.toFixed(1)} ${units[idx]}`;
};
const formatUptime = (sec=0) => {
  const d = Math.floor(sec/86400);
  const h = Math.floor((sec%86400)/3600);
  const m = Math.floor((sec%3600)/60);
  if (d>0) return `${d}天${h}小时`;
  if (h>0) return `${h}小时${m}分`;
  return `${m}分`;
};

function NodeList({ onSelect, onShowInstall }) {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try {
      setData(await api('GET', '/api/nodes'));
    } catch (e) { message.error(e.message); }
    setLoading(false);
  };
  useEffect(() => {
    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, []);

  const onCreate = async () => {
    try {
      const v = await form.validateFields();
      await api('POST', '/api/nodes', v);
      message.success('节点已创建');
      setModalOpen(false);
      form.resetFields();
      load();
    } catch (e) { message.error(e.message); }
  };

  return (
    <Card title="节点列表" extra={<Button type="primary" onClick={()=>setModalOpen(true)}>新建节点</Button>}>
      <Row gutter={[16,16]}>
        {data.map(n=>(
          <Col key={n.id} xs={24} sm={12} md={8} lg={6}>
            <Card title={n.name} size="small" extra={<Tag color="blue">{n.transport?.toUpperCase()||'QUIC'}</Tag>}>
              <Space direction="vertical" size={6} style={{width:'100%'}}>
                <Statistic title="CPU" value={n.cpu_usage?.toFixed ? n.cpu_usage.toFixed(1) : 0} suffix="%" />
                <Statistic title="内存" value={`${formatBytes(n.mem_used_bytes||0)} / ${formatBytes(n.mem_total_bytes||0)}`} />
                <Statistic title="运行时长" value={formatUptime(n.uptime_sec||0)} />
                <Statistic title="网络累计" value={`↑${formatBytes(n.net_out_bytes||0)} ↓${formatBytes(n.net_in_bytes||0)}`} />
                <div>版本：{n.node_version || '-'}</div>
                <div>系统/架构：{n.os_name || '-'} / {n.arch || '-'}</div>
                <div>上次心跳：{n.last_seen_at ? new Date(n.last_seen_at).toLocaleString() : '-'}</div>
                <Space>
                  <Button size="small" type="primary" onClick={()=>onSelect(n)}>管理</Button>
                  <Button size="small" onClick={()=>onShowInstall(n)}>安装</Button>
                </Space>
              </Space>
            </Card>
          </Col>
        ))}
      </Row>
      <Modal open={modalOpen} onCancel={()=>setModalOpen(false)} onOk={onCreate} title="新建节点">
        <Form layout="vertical" form={form} initialValues={{ ws_listen: ":18080", metrics_listen: ":19090" }}>
        <Form.Item name="name" label="节点名称" rules={[{required:true}]}><Input/></Form.Item>
        <Form.Item name="ws_listen" label="WS监听"/><Form.Item name="metrics_listen" label="Metrics监听"/>
        <Form.Item name="quic_listen" label="QUIC监听 (可选)"><Input placeholder="不填则与WS相同"/></Form.Item>
        <Form.Item name="wss_listen" label="WSS监听 (可选)" tooltip="如需同时启用 WSS，请填写监听端口"><Input placeholder="例如 :18443"/></Form.Item>
        <Form.Item name="quic_server_name" label="QUIC Server Name (可选)" tooltip="空则跳过证书校验，可用IP直连；填域名则按域名校验">
          <Input placeholder="如需校验证书请填写域名"/>
        </Form.Item>
          <Form.Item name="transport" label="传输" rules={[{required:true}]}>
            <Select options={[{value:'wss',label:'WSS'},{value:'quic',label:'QUIC(TCP)'}]}/>
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

function NodeDetail({ node, onBack, refreshList, onShowInstall }) {
  const [detail, setDetail] = useState(node);
  const [entryOpen, setEntryOpen] = useState(false);
  const [peerOpen, setPeerOpen] = useState(false);
  const [allNodes, setAllNodes] = useState([]);
  const [routeOpen, setRouteOpen] = useState(false);
  const [routeEditOpen, setRouteEditOpen] = useState(false);
  const [routeForm] = Form.useForm();
  const [routeEditForm] = Form.useForm();
  const [editOpen, setEditOpen] = useState(false);
  const [entryForm] = Form.useForm();
  const [peerForm] = Form.useForm();
  const [peerEditOpen, setPeerEditOpen] = useState(false);
  const [peerEditForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const [peerIPOptions, setPeerIPOptions] = useState([]);
  const [peerEditIPOptions, setPeerEditIPOptions] = useState([]);

  const load = async () => {
    try {
      setDetail(await api('GET', `/api/nodes/${node.id}`));
      refreshList();
      setAllNodes(await api('GET', '/api/nodes'));
    } catch (e) { message.error(e.message); }
  };
  useEffect(() => { load(); }, [node.id]);

  const nodePublicIPs = (name) => {
    const n = (allNodes || []).find(x => x.name === name);
    if (!n || !Array.isArray(n.public_ips)) return [];
    return n.public_ips.filter(Boolean);
  };

  useEffect(() => {
    const name = peerForm.getFieldValue('peer_name');
    if (name) setPeerIPOptions(nodePublicIPs(name));
    const editName = peerEditForm.getFieldValue('peer_name');
    if (editName) setPeerEditIPOptions(nodePublicIPs(editName));
  }, [allNodes]);

  const addEntry = async () => {
    try {
      const v = await entryForm.validateFields();
      await api('POST', `/api/nodes/${node.id}/entries`, v);
      message.success('入口已添加'); setEntryOpen(false); entryForm.resetFields(); load();
    } catch (e) { message.error(e.message); }
  };
  const addPeer = async () => {
    try {
      const v = await peerForm.validateFields();
      await api('POST', `/api/nodes/${node.id}/peers`, v);
      message.success('对端已添加'); setPeerOpen(false); peerForm.resetFields(); load();
    } catch (e) { message.error(e.message); }
  };
  const addRoute = async () => {
    try {
      const v = await routeForm.validateFields();
      await api('POST', `/api/nodes/${node.id}/routes`, v);
      message.success('线路已添加'); setRouteOpen(false); routeForm.resetFields(); load();
    } catch (e) { message.error(e.message); }
  };
  const removeNode = async () => {
    Modal.confirm({
      title: '确认删除节点？',
      onOk: async () => {
        await api('DELETE', `/api/nodes/${node.id}`);
        message.success('已删除'); onBack(); refreshList();
      }
    });
  };

  const entryCols = [
    { title: '监听', dataIndex: 'listen' },
    { title: '协议', dataIndex: 'proto' },
    { title: '出口节点', dataIndex: 'exit' },
    { title: '远端', dataIndex: 'remote' },
  ];
  const peerCols = [
    { title: '名称', dataIndex: 'peer_name' },
    { title: '入口IP', dataIndex: 'entry_ip' },
    { title: '出口IP', dataIndex: 'exit_ip' },
    { title: 'WS地址', dataIndex: 'endpoint' },
    { title: '操作',
      render:(_,r)=><Space>
        <Button size="small" onClick={()=>{
          peerEditForm.setFieldsValue(r);
          setPeerEditIPOptions(nodePublicIPs(r.peer_name));
          setPeerEditOpen(true);
        }}>编辑</Button>
        <Button danger size="small" onClick={()=>{
          Modal.confirm({title:'确认删除对端？', onOk: async ()=>{
            try{
              await api('DELETE', `/api/nodes/${node.id}/peers/${r.id}`);
              message.success('已删除');
              load();
            }catch(e){ message.error(e.message); }
          }})
        }}>删除</Button>
      </Space>
    }
  ];
  const routeCols = [
    { title: '名称', dataIndex: 'name' },
    { title: '出口', dataIndex: 'exit' },
    { title: '远端', dataIndex: 'remote' },
    { title: '优先级', dataIndex: 'priority' },
    { title: '路径', dataIndex: 'path', render:(p=[])=>p.map(n=><Tag key={n}>{n}</Tag>) },
    { title: '操作',
      render:(_,r)=><Space>
        <Button size="small" onClick={()=>{routeEditForm.setFieldsValue({...r}); setRouteEditOpen(true);}}>编辑</Button>
        <Button danger size="small" onClick={()=>{
          Modal.confirm({title:'确认删除线路？', onOk: async ()=>{
            try{
              await api('DELETE', `/api/nodes/${node.id}/routes/${r.id}`);
              message.success('已删除');
              load();
            }catch(e){ message.error(e.message); }
          }});
        }}>删除</Button>
      </Space>
    }
  ];

  return (
    <Card title={`节点：${detail.name}`} extra={<Space>
      <Button onClick={onBack}>返回</Button>
      <Button href={`/nodes/${detail.id}/config`} target="_blank">下载配置</Button>
      <Button onClick={() => onShowInstall(detail)}>安装脚本</Button>
      <Button onClick={()=>{editForm.setFieldsValue({
        ws_listen: detail.ws_listen,
        wss_listen: detail.wss_listen,
        metrics_listen: detail.metrics_listen,
        poll_period: detail.poll_period||'5s',
        quic_listen: detail.quic_listen || detail.ws_listen,
        quic_server_name: detail.quic_server_name || '',
      }); setEditOpen(true);}}>编辑监听</Button>
      <Button danger onClick={removeNode}>删除</Button>
    </Space>}>
      <Descriptions column={2} bordered size="small">
        <Descriptions.Item label="WS监听">{detail.ws_listen}</Descriptions.Item>
        <Descriptions.Item label="Metrics">{detail.metrics_listen}</Descriptions.Item>
        <Descriptions.Item label="AuthKey">{detail.auth_key}</Descriptions.Item>
        <Descriptions.Item label="UDP TTL">{detail.udp_session_ttl}</Descriptions.Item>
        <Descriptions.Item label="Poll周期">{detail.poll_period || '5s'}</Descriptions.Item>
        <Descriptions.Item label="压缩(全局)">{detail.compression || 'gzip'}</Descriptions.Item>
        <Descriptions.Item label="压缩阈值(全局)">{detail.compression_min_bytes || 0} Bytes</Descriptions.Item>
        <Descriptions.Item label="传输(全局)">{(detail.transport||'wss').toUpperCase()}</Descriptions.Item>
        <Descriptions.Item label="QUIC监听">{detail.quic_listen || detail.ws_listen}</Descriptions.Item>
        <Descriptions.Item label="WSS监听">{detail.wss_listen || '-'}</Descriptions.Item>
        <Descriptions.Item label="CPU">{(detail.cpu_usage||0).toFixed ? detail.cpu_usage.toFixed(1)+'%' : '-'}</Descriptions.Item>
        <Descriptions.Item label="内存">{`${formatBytes(detail.mem_used_bytes||0)} / ${formatBytes(detail.mem_total_bytes||0)}`}</Descriptions.Item>
        <Descriptions.Item label="运行时长">{formatUptime(detail.uptime_sec||0)}</Descriptions.Item>
        <Descriptions.Item label="网络累计">{`↑${formatBytes(detail.net_out_bytes||0)} ↓${formatBytes(detail.net_in_bytes||0)}`}</Descriptions.Item>
        <Descriptions.Item label="版本">{detail.node_version || '-'}</Descriptions.Item>
        <Descriptions.Item label="最后心跳">{detail.last_seen_at ? new Date(detail.last_seen_at).toLocaleString() : '-'}</Descriptions.Item>
      </Descriptions>
      <Tabs style={{marginTop:16}} items={[
        { key:'entries', label:'入口', children:<>
          <Button type="primary" onClick={()=>setEntryOpen(true)} style={{marginBottom:8}}>添加入口</Button>
      <Table rowKey="id" dataSource={detail.entries||[]} columns={[...entryCols,{
        title:'操作',
        render:(_,r)=><Button danger size="small" onClick={()=>{
          Modal.confirm({
            title:'确认删除入口？',
            onOk: async ()=>{
              try{
                await api('DELETE', `/api/nodes/${detail.id}/entries/${r.id}`);
                message.success('已删除');
                load();
              }catch(e){ message.error(e.message); }
            }
          });
        }}>删除</Button>
      }]} pagination={false}/>
        </>},
        { key:'peers', label:'对端', children:<>
          <Button type="primary" onClick={()=>setPeerOpen(true)} style={{marginBottom:8}}>添加对端</Button>
          <Table rowKey="id" dataSource={detail.peers||[]} columns={peerCols} pagination={false}/>
        </>},
        { key:'routes', label:'线路', children:<>
          <Space style={{marginBottom:8}}>
            <Button type="primary" onClick={()=>setRouteOpen(true)}>添加线路</Button>
            <span>
              节点公网IP：
              {(detail.public_ips||[]).length
                ? (detail.public_ips||[]).map(ip=><Tag key={ip}>{ip}</Tag>)
                : '未上报'}
            </span>
          </Space>
          <Table rowKey="id" dataSource={detail.routes||[]} columns={routeCols} pagination={false}/>
        </>}
      ]}/>

      <Modal open={entryOpen} onCancel={()=>setEntryOpen(false)} onOk={addEntry} title="添加入口">
        <Form layout="vertical" form={entryForm} initialValues={{ proto:"tcp" }}>
          <Form.Item name="listen" label="监听" rules={[{required:true}]}><Input placeholder=":10080"/></Form.Item>
          <Form.Item name="proto" label="协议" rules={[{required:true}]}>
            <Select
              options={[
                {value:'tcp',label:'tcp'},
                {value:'udp',label:'udp'},
                {value:'both',label:'tcp+udp'},
              ]}
            />
          </Form.Item>
          <Form.Item name="exit" label="出口节点" rules={[{required:true}]}>
            <Select
              placeholder="选择出口节点"
              options={(allNodes||[]).filter(n=>n.id!==detail.id).map(n=>({label:n.name,value:n.name}))}
              showSearch
              optionFilterProp="label"
            />
          </Form.Item>
          <Form.Item name="remote" label="远端" rules={[{required:true}]}><Input placeholder="1.1.1.1:3389"/></Form.Item>
        </Form>
      </Modal>

      <Modal open={peerEditOpen} onCancel={()=>setPeerEditOpen(false)} onOk={async ()=>{
        try {
          const v = await peerEditForm.validateFields();
          await api('PUT', `/api/nodes/${node.id}/peers/${v.id}`, v);
          message.success('已更新');
          setPeerEditOpen(false);
          load();
        } catch (e) { message.error(e.message); }
      }} title="编辑对端">
        <Form layout="vertical" form={peerEditForm}>
          <Form.Item name="id" hidden><Input/></Form.Item>
          <Form.Item name="peer_name" label="对端节点" rules={[{required:true}]}>
            <Select
              placeholder="选择已有节点"
              options={(allNodes || []).filter(n=>n.id!==detail.id).map(n=>({label:n.name, value:n.name}))}
              showSearch
              optionFilterProp="label"
              onChange={(val)=>{setPeerEditIPOptions(nodePublicIPs(val)); peerEditForm.setFieldsValue({entry_ip: undefined, exit_ip: undefined});}}
            />
          </Form.Item>
          <Form.Item name="entry_ip" label="入口IP (可选)">
            <Select
              placeholder="从对端公网IP选择，可不选"
              allowClear
              options={peerEditIPOptions.map(ip=>({label:ip, value:ip}))}
            />
          </Form.Item>
          <Form.Item name="exit_ip" label="出口IP (可选)">
            <Select
              placeholder="从对端公网IP选择，可不选"
              allowClear
              options={peerEditIPOptions.map(ip=>({label:ip, value:ip}))}
            />
          </Form.Item>
          <Form.Item name="endpoint" label="WS地址 (可选)"><Input placeholder="如留空则尝试根据入口IP+对端监听拼装"/></Form.Item>
        </Form>
      </Modal>

      <Modal open={peerOpen} onCancel={()=>setPeerOpen(false)} onOk={addPeer} title="添加对端">
        <Form layout="vertical" form={peerForm}>
          <Form.Item name="peer_name" label="对端节点" rules={[{required:true}]}>
            <Select
              placeholder="选择已有节点"
              options={(allNodes || []).filter(n=>n.id!==detail.id).map(n=>({label:n.name, value:n.name}))}
              showSearch
              optionFilterProp="label"
              onChange={(val)=>{setPeerIPOptions(nodePublicIPs(val)); peerForm.setFieldsValue({entry_ip: undefined, exit_ip: undefined});}}
            />
          </Form.Item>
          <Form.Item name="entry_ip" label="入口IP (可选)">
            <Select
              placeholder="从对端公网IP选择，可不选"
              allowClear
              options={peerIPOptions.map(ip=>({label:ip, value:ip}))}
            />
          </Form.Item>
          <Form.Item name="exit_ip" label="出口IP (可选)">
            <Select
              placeholder="从对端公网IP选择，可不选"
              allowClear
              options={peerIPOptions.map(ip=>({label:ip, value:ip}))}
            />
          </Form.Item>
          <Form.Item name="endpoint" label="WS地址 (可选)">
            <Input placeholder="如留空则尝试根据入口IP+对端监听拼装"/>
          </Form.Item>
        </Form>
      </Modal>

      <Modal open={editOpen} onCancel={()=>setEditOpen(false)} onOk={async ()=>{
        try {
          const v = await editForm.validateFields();
          await api('PUT', `/api/nodes/${detail.id}`, v);
          message.success('已更新');
          setEditOpen(false);
          load();
        } catch (e) { message.error(e.message); }
      }} title="编辑监听端口">
        <Form layout="vertical" form={editForm}>
          <Form.Item name="ws_listen" label="WS监听" rules={[{required:true}]}><Input placeholder=":18080"/></Form.Item>
          <Form.Item name="wss_listen" label="WSS监听 (可选)" tooltip="如需启用 WSS 请填写"><Input placeholder=":18443"/></Form.Item>
          <Form.Item name="metrics_listen" label="Metrics监听" rules={[{required:true}]}><Input placeholder=":19090"/></Form.Item>
          <Form.Item name="poll_period" label="Poll周期" rules={[{required:true}]}><Input placeholder="5s"/></Form.Item>
          <Form.Item name="quic_listen" label="QUIC监听 (可选)" tooltip="不填则与 WS 监听相同">
            <Input placeholder=":18090"/>
          </Form.Item>
          <Form.Item name="quic_server_name" label="QUIC Server Name (可选)" tooltip="空则跳过证书校验，可用IP直连；填域名则按域名校验">
            <Input placeholder="如需校验证书请填写域名"/>
          </Form.Item>
        </Form>
      </Modal>

      <Modal open={routeOpen} onCancel={()=>setRouteOpen(false)} onOk={addRoute} title="添加线路" width={600}>
        <Form layout="vertical" form={routeForm} initialValues={{priority:1}}>
          <Form.Item name="name" label="线路名称" rules={[{required:true}]}><Input placeholder="如: 成都->新加坡-1"/></Form.Item>
          <Form.Item name="exit" label="出口节点" rules={[{required:true}]}>
            <Select
              placeholder="选择出口节点"
              options={(allNodes||[]).filter(n=>n.id!==detail.id).map(n=>({label:n.name,value:n.name}))}
              showSearch optionFilterProp="label"
            />
          </Form.Item>
          <Form.Item name="priority" label="优先级" rules={[{required:true}]}><Input type="number" min={1}/></Form.Item>
          <Form.Item name="path" label="路径节点顺序" rules={[{required:true, message:'请选择路径'}]}>
            <Select
              mode="multiple"
              placeholder="从起点到出口的节点顺序"
              options={(allNodes||[]).map(n=>({label:n.name,value:n.name}))}
              showSearch optionFilterProp="label"
            />
          </Form.Item>
          <Divider>可选：入口/出口 IP 参考</Divider>
          <Space direction="vertical" style={{width:'100%'}}>
            <div>
              节点公网IP：
              {(detail.public_ips||[]).length
                ? (detail.public_ips||[]).map(ip=><Tag key={ip}>{ip}</Tag>)
                : '未上报'}
            </div>
          </Space>
        </Form>
      </Modal>

      <Modal open={routeEditOpen} onCancel={()=>setRouteEditOpen(false)} onOk={async ()=>{
        try {
          const v = await routeEditForm.validateFields();
          await api('PUT', `/api/nodes/${node.id}/routes/${v.id}`, v);
          message.success('已更新');
          setRouteEditOpen(false);
          load();
        } catch (e) { message.error(e.message); }
      }} title="编辑线路" width={600}>
        <Form layout="vertical" form={routeEditForm}>
          <Form.Item name="id" hidden><Input/></Form.Item>
          <Form.Item name="name" label="线路名称" rules={[{required:true}]}><Input/></Form.Item>
          <Form.Item name="exit" label="出口节点" rules={[{required:true}]}>
            <Select
              placeholder="选择出口节点"
              options={(allNodes||[]).filter(n=>n.id!==detail.id).map(n=>({label:n.name,value:n.name}))}
              showSearch optionFilterProp="label"
            />
          </Form.Item>
          <Form.Item name="priority" label="优先级" rules={[{required:true}]}><Input type="number" min={1}/></Form.Item>
          <Form.Item name="path" label="路径节点顺序" rules={[{required:true}]}>
            <Select
              mode="multiple"
              placeholder="从起点到出口的节点顺序"
              options={(allNodes||[]).map(n=>({label:n.name,value:n.name}))}
              showSearch optionFilterProp="label"
            />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

export default function App() {
  const [selected, setSelected] = useState(null);
  const [tick, setTick] = useState(0);
  const [installCmd, setInstallCmd] = useState('');
  const [installOpen, setInstallOpen] = useState(false);
  const [settings, setSettings] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('jwt')||'');
  const [loginOpen, setLoginOpen] = useState(!localStorage.getItem('jwt'));
  const [userList, setUserList] = useState([]);
  const [userModal, setUserModal] = useState(false);
  const [userForm] = Form.useForm();
  const [editUser, setEditUser] = useState(null);
  const refreshList = ()=> setTick(t=>t+1);

  const showInstall = (node) => {
    const origin = window.location.origin;
    const tok = node.token || '';
    const tokenArg = tok ? `?token=${encodeURIComponent(tok)}` : '';
    const extra = tok ? ` -k ${tok}` : '';
    setInstallCmd(`curl -fsSL ${origin}/nodes/${node.id}/install.sh${tokenArg} | bash -s --${extra}`);
    setInstallOpen(true);
  };
  const loadSettings = async () => {
    try {
      if(!token) return;
      const s = await api('GET', '/api/settings');
      if (s) setSettings(s);
    } catch (e) {
      if(token) message.error('全局设置加载失败: '+e.message);
    }
  };
  const copyCmd = async () => {
    try {
      await navigator.clipboard.writeText(installCmd);
      message.success('已复制');
    } catch (e) {
      message.error('复制失败');
    }
  };

  const login = async (vals) => {
    try {
      const res = await api('POST', '/api/login', vals);
      localStorage.setItem('jwt', res.token);
      setToken(res.token);
      setLoginOpen(false);
      message.success('登录成功');
      loadSettings();
      refreshList();
    } catch (e) {
      message.error(e.message);
    }
  };
  const logout = () => {
    localStorage.removeItem('jwt');
    setToken('');
    setSelected(null);
    setLoginOpen(true);
  };

  const loadUsers = async () => {
    try {
      const res = await api('GET', '/api/users');
      setUserList(res);
    } catch (e) {
      if(token) message.error('加载用户失败: '+e.message);
    }
  };
  useEffect(()=>{ if(token){ loadUsers(); } }, [token]);

  useEffect(() => { if(token) loadSettings(); }, [token]);

  const SettingsCard = () => {
    const [form] = Form.useForm();
    const [saving, setSaving] = useState(false);
    useEffect(()=>{ if(settings) form.setFieldsValue({
      transport: settings.transport || 'quic',
      compression: settings.compression || 'none',
      compression_min_bytes: settings.compression_min_bytes || 0,
      debug_log: settings.debug_log || false,
    }); }, [settings]);
    const onSave = async () => {
      try {
        const v = await form.validateFields();
        setSaving(true);
        await api('POST', '/api/settings', v);
        message.success('全局设置已更新，节点下次拉取配置后生效');
        await loadSettings();
      } catch (e) { message.error(e.message); }
      setSaving(false);
    };
    return (
      <Card title="全局传输与压缩设置" style={{marginBottom:16}}>
        <Form layout="inline" form={form}>
          <Form.Item name="transport" label="传输" rules={[{required:true}]}>
            <Select style={{width:200}} options={[{value:'wss',label:'WSS'},{value:'quic',label:'QUIC(TCP)'}]}/>
          </Form.Item>
          <Form.Item name="compression" label="压缩" rules={[{required:true}]} style={{marginLeft:16}}>
            <Select style={{width:200}} options={[
              {value:'none', label:'关闭'},
              {value:'gzip', label:'gzip'},
            ]}/>
          </Form.Item>
          <Form.Item name="compression_min_bytes" label="压缩阈值(Bytes)" tooltip="小于该大小直传不压缩，0表示总是压缩" style={{marginLeft:16}}>
            <Input type="number" min={0} style={{width:200}}/>
          </Form.Item>
          <Form.Item name="debug_log" label="调试日志" style={{marginLeft:16}}>
            <Select style={{width:140}} options={[{value:true,label:'开启'},{value:false,label:'关闭'}]}/>
          </Form.Item>
          <Form.Item>
            <Button type="primary" onClick={onSave} loading={saving}>保存</Button>
          </Form.Item>
        </Form>
      </Card>
    );
  };

  if (!token) {
    return (
      <Layout style={{minHeight:'100vh'}}>
        <Header style={{color:'#fff', fontSize:18}}>ARouter 控制台</Header>
        <Content style={{padding:24}}>
          <Card title="登录">
            <Form layout="vertical" onFinish={login}>
              <Form.Item name="username" label="用户名" rules={[{required:true}]}><Input/></Form.Item>
              <Form.Item name="password" label="密码" rules={[{required:true}]}><Input.Password/></Form.Item>
              <Button type="primary" htmlType="submit">登录</Button>
            </Form>
          </Card>
        </Content>
      </Layout>
    );
  }

  return (
    <Layout style={{minHeight:'100vh'}}>
      <Header style={{color:'#fff', fontSize:18, display:'flex', justifyContent:'space-between'}}>
        <div>ARouter 控制台</div>
        <Space>
          <Button size="small" onClick={logout}>退出</Button>
          <Button size="small" onClick={()=>{setEditUser(null); userForm.resetFields(); setUserModal(true);}}>用户管理</Button>
        </Space>
      </Header>
      <Content style={{padding:24}}>
        <SettingsCard/>
        {selected
          ? <NodeDetail key={selected.id} node={selected} onBack={()=>setSelected(null)} refreshList={refreshList} onShowInstall={showInstall}/>
          : <NodeList key={tick} onSelect={setSelected} onShowInstall={showInstall}/>
        }
        <Modal open={installOpen} onCancel={()=>setInstallOpen(false)} onOk={copyCmd} okText="复制命令">
          <p>在目标节点执行以下命令以安装并自启动：</p>
          <Input.TextArea value={installCmd} rows={3} readOnly />
        </Modal>
        <Modal open={userModal} onCancel={()=>{setUserModal(false); setEditUser(null); userForm.resetFields();}} onOk={async ()=>{
          try {
            const v = await userForm.validateFields();
            if(editUser){
              const body = {};
              if(v.password) body.password = v.password;
              if(v.is_admin!==undefined) body.is_admin = v.is_admin;
              await api('PUT', `/api/users/${editUser.id}`, body);
              message.success('用户已更新');
            } else {
              await api('POST', '/api/users', v);
              message.success('用户已创建');
            }
            setUserModal(false);
            setEditUser(null);
            userForm.resetFields();
            loadUsers();
          } catch (e){ message.error(e.message); }
        }} title="用户管理" okText={editUser?'保存':'添加用户'}>
          <Table rowKey="id" dataSource={userList} pagination={false} columns={[
            {title:'用户名', dataIndex:'username'},
            {title:'管理员', dataIndex:'is_admin', render:v=>v?'是':'否'},
            {title:'操作', render:(_,r)=><Space>
              <Button size="small" onClick={()=>{setEditUser(r); userForm.setFieldsValue({username:r.username,is_admin:r.is_admin,password:''}); setUserModal(true);}}>修改</Button>
              <Button size="small" danger onClick={async ()=>{
                try{ await api('DELETE', `/api/users/${r.id}`); message.success('已删除'); loadUsers(); }
                catch(e){ message.error(e.message); }
              }}>删除</Button>
            </Space>}
          ]}/>
          <Divider/>
          <Form layout="vertical" form={userForm}>
            <Form.Item name="username" label="用户名" rules={[{required:true}]}><Input/></Form.Item>
            <Form.Item name="password" label="密码" rules={[{required:true}]}><Input.Password/></Form.Item>
            <Form.Item name="is_admin" label="管理员" initialValue={false}>
              <Select options={[{value:true,label:'是'},{value:false,label:'否'}]}/>
            </Form.Item>
          </Form>
        </Modal>
      </Content>
    </Layout>
  );
}
