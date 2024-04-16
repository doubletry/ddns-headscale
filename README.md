# ddns-headscale

将headscale上的各个node与子域名绑定，格式为 机器名```Name``` + 用户名```User``` + 域名```Domain```，如机器名为```abc```，用户名为```zhangsan```，域名为```example.com```，则对应的node的子域名为```abc.zhangsan.example.com```

## 使用方法
本仓库使用poetry做包管理，poetry安装命令如下：
```
curl -sSL https://install.python-poetry.org | python3 -
``` 
详情见: [Poetry](https://python-poetry.org/docs/#installing-with-the-official-installer)

### 1. 复制config.yml.example为config.yml，并填写

目前仅支持腾讯云
domain为域名
user_id为腾讯云域名解析的user_id
user_token为腾讯云域名解析的user_token

### 2. 复制domains.json.example为domain.json
初始时为空即可，后续会自动更新

### 3. 添加环境

```
poetry install
```

### 4. 执行域名更新

```
poetry run python main.py
```