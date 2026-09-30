# PXN Development Credentials

本仓库提供PXN产品开发和自动化测试共用的凭据工具、公钥和指纹清单。开发私钥保存在随仓库版本化提交的 `private/` 目录；克隆本仓后即可直接执行签发和完整凭据校验。所有材料仅用于开发环境，不用于量产、客户交付或生产签名。

## 提供内容

- P-256开发根CA和设备签发CA；
- P-256 Host授权签名密钥；
- P-256 OTA组件签名密钥；
- 开发设备身份签发工具；
- XProtocol 认证 CSR 生成和外部签发证书校验工具；
- 公钥、证书、Key ID和SHA-256清单；
- 仓库完整性校验工具。

产品集成仓只保存随机开发UUID、凭据集ID和公钥指纹，不复制本仓私钥。本仓不是固件编译submodule，签发输出默认写入`issued/`并由Git忽略。

## 初始化和校验

仓库首次建立时生成一次凭据：

```powershell
python -m pip install -r requirements.txt
python tools/generate_credentials.py
python tools/validate_repository.py
```

生成器在凭据已存在时拒绝覆盖。轮换开发凭据必须建立新凭据集版本，不能覆盖已经被产品集成仓引用的公钥指纹。

## 签发开发设备身份

使用产品集成仓提供的`development/identity.yaml`：

```powershell
python tools/issue_device_identity.py `
  --identity-file <product-integration>/development/identity.yaml `
  --target <target-key> `
  --output issued/<target-key>
```

命令默认使用产品仓中稳定的开发UUID，并为本次签发生成随机128位唯一code。多台同类型设备同时联调时使用新的随机UUID：

```powershell
python tools/issue_device_identity.py `
  --identity-file <product-integration>/development/identity.yaml `
  --target <target-key> `
  --random-device-uuid `
  --output issued/<target-key>-02
```

输出包括设备私钥、叶证书、DER证书、`PXN_X509_CHAIN_V1`对象、`identity.json`和可直接加入嵌入式开发构建的`pxn-development-identity.h`。头文件包含开发设备私钥和统一验证公钥，只能用于本地开发构建，不得提交产品集成仓或进入生产固件。

产品构建系统必须为量产配置统一定义`PXN_PRODUCTION_BUILD=1`。生成头文件检测到该宏会触发编译错误，从而阻止开发设备私钥、开发证书和开发信任公钥进入量产镜像。开发构建不需要额外开关；只需将签发输出目录加入本地include路径。固件源码通过`PXN_DEVELOPMENT_IDENTITY`判断当前是否编入开发身份。

## XProtocol 认证初始化边界

开发联调的授权工具可以在受控开发环境中自动完成“生成本机密钥和 CSR → 使用同一 station 临时测试 issuer 签发 → 校验证书 → 原子提交本地凭据目录”的软件闭环：

```powershell
python tools/provision_auth_development.py `
  --station <controlled-development-station> `
  --device-name dev-unit-a `
  --trust-generation 3 `
  --output <private-output>
```

该命令第一次运行时在受控 station 目录创建临时测试 CA，后续设备复用同一开发信任域；station issuer 私钥不进入设备目录或固件包。完成后可重复执行并得到幂等结果，中断在原子提交前时下一次执行会恢复已重新校验的 staging 目录。它只产生开发域本地测试凭据，`production_eligible` 始终为 `false`，不能代替空片、设备存储、重启或生产资格证据。`--environment production` 明确拒绝，生产必须调用外部生产签发和受控产线工具。修改证书、CSR、设备密钥、trust generation 或文件后，幂等/恢复路径都会拒绝结果。

认证通道使用独立的 P-256 设备密钥和 X.509 mutual-TLS 证书。设备端或受控配置端可先生成本机密钥和 CSR：

```powershell
python tools/create_auth_csr.py `
  --environment development `
  --trust-generation 3 `
  --common-name device-local `
  --output <private-output>
```

`create_auth_csr.py` 不读取签发私钥、不自动安装证书；生产流程必须把 CSR 交给外部受控签发系统。签发后可用 `validate_auth_credential.py` 检查证书的 P-256、mutual-TLS 用途、环境、trust generation、CSR 公钥和可选 issuer 签名关系：

```powershell
python tools/validate_auth_credential.py `
  --certificate <signed-certificate.pem> `
  --issuer <trust-issuer.pem> `
  --csr <device-auth.csr.pem> `
  --environment development `
  --trust-generation 3
```

校验结果中的 `provisioned: false` 是有意保留的边界：profile/manifest 或证书校验不能代替设备存储安装、首次启动和生产资格证据。认证设备私钥不与 Host 授权签名、OTA 签名或固件签名材料复用；生产根和生产 issuer 也不由本仓库生成或配置。

## 使用边界

- 私钥只允许存在于受控开发环境和本私有仓；
- 开发固件、Host配置和测试报告必须标记`environment: development`；
- 产品仓不得把开发密钥声明为生产信任根；
- 量产设备UUID、设备私钥、证书和唯一code由生产配置系统逐设备生成；
- 发现开发私钥泄露时创建新凭据集并更新产品仓指纹，不复用原Key ID。
