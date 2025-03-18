# 调整nornir默认超时(在defaults.yaml添加)
connection_options:
  netmiko:
    extras:
      timeout: 60 
      session_timeout: 120
