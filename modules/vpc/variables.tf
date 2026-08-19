variable "vpc_name" {
    description = "VPC 이름"
    type = string
    default = "WHS_VPC"
}

variable "vpc_cidr" {
    description = "VPC CIDR 블럭"
    type = string
    default = "10.3.0.0/16"
}

variable "availability_zones" {
    description = "가용 영역"
    type = list(string)
    default = ["ap-northeast-2a", "ap-northeast-2b"]
}

variable "public_subnet_cidrs" {
    description = "Public 서브넷 CIDR"
    type = list(string)
    default = ["10.3.1.0/24", "10.3.2.0/24"]
}

variable "private_subnet_cidrs" {
    description = "Private 서브넷 CIDR"
    type = list(string)
    default = ["10.3.11.0/24", "10.3.12.0/24"]
}