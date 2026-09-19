# Terraform provider 잠금: 공식 6.60.0 공개 checksum 목록과 로컬 Windows h1을 사용합니다.
provider "registry.terraform.io/hashicorp/aws" { # 공개 provider 배포물을 고정합니다.
  version = "6.60.0" # 로컬 schema 검증에 사용한 버전입니다.
  constraints = "~> 6.0" # 설정의 버전 제약과 같습니다.
  hashes = [ # 플랫폼별 배포 ZIP의 공식 SHA-256을 포함합니다.
    "h1:aKdhZmlQi4A+18NUfL41TdCSDL94nB5hrpHUSx/bh7w=", # 로컬 Windows 패키지 내용 해시입니다.
    "zh:268d711a0a9c18459e09a837405244e5d459bb4ebb5d34a91c4fcbabe3e25d26", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:5210c99d5946dd4985a6cff7460422e257037679b35df0a54982e3f675d1a8d5", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:e087e5e6e3130980838552022e022a62a52a851cf93a0029cb5d410a34f6106b", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:effc513566df2f5b5921a5df884817b1de57790db1c485eece566c5d4c55c4ee", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:2e1cddc362497b569ba528f013d0cf770465047b8185e8180f4ccabafa082577", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:caf78d1713cc323383facae063c61584758ea697428f328600227902f3a9980f", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:b4268c98208f725ea28afb38dde6cb4b7536de577c36ee919fa44c3d8d5faf70", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:fb7ef7e405b05789cec32c8ea06a353789c6e3a336b876508cf2ac98984f0558", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:904f0651e9bfbf08b16f4d13c85e7841c2d1b5a670087cb11f8d4ad06249cf0c", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:e94318f9ebf29d06aa821da73a7fc7a637d7d13e535e40585c6242cea4477262", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:60703aa30b23ed5e5cfabf2614aeb465cf2aa4b848eb8afb2723b6b9d358ccd0", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:f2be12b976d10a91289835056ff962721e65f47f8e52b368211c4bd3ce9e20e6", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:1a29660d9038c38e9e306194bd3e7de7017148f3491af7fdfa434d7d8c82b3d4", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:2d7058c285484e7cccf4f5b1973c10b404ae77532f77ea95115915dd341fbf5b", # HashiCorp HTTPS 공개 checksum입니다.
    "zh:cb349f8a43653bfc78867909d6342c56073f9805bdbd9dc32a8e1d18302257d4", # HashiCorp HTTPS 공개 checksum입니다.
  ] # checksum 목록을 마칩니다.
} # provider 잠금을 마칩니다.
