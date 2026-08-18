# VPC 생성
resource "aws_vpc" "this" {
    cidr_block = var.vpc_cidr
    enable_dns_support = true
    enable_dns_hostnames = true

    tags = {
        Name = var.vpc_name
    }
}

# Public Subnet 생성
resource "aws_subnet" "public" {
    count = length(var.availability_zones)

    vpc_id = aws_vpc.this.id
    cidr_block = var.public_subnet_cidrs[count.index]
    availability_zone = var.availability_zones[count.index]
    map_public_ip_on_launch = true

    tags = {
        Name = "${var.vpc_name}-Public-Subnet-${count.index + 1}"
    }
}

# Private Subnet 생성
resource "aws_subnet" "private" {
    count = length(var.availability_zones)

    vpc_id = aws_vpc.this.id
    cidr_block = var.private_subnet_cidrs[count.index]
    availability_zone = var.availability_zones[count.index]

    tags = {
        Name = "${var.vpc_name}-Private-Subnet-${count.index + 1}"
    }
}

# Internet Gateway 생성
resource "aws_internet_gateway" "this" {
    vpc_id = aws_vpc.this.id

    tags = {
        Name = "${var.vpc_name}-IGW"
    }
}

# Public Routing Table 생성
resource "aws_route_table" "public" {
    vpc_id = aws_vpc.this.id
    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.this.id
    }
    tags = {
        Name = "${var.vpc_name}-Public-RT"
    }
}
resource "aws_route_table_association" "public" {
    count = length(var.availability_zones)

    subnet_id = aws_subnet.public[count.index].id
    route_table_id = aws_route_table.public.id
}

# NAT Gateway 생성
resource "aws_eip" "nat" {
    count = length(var.availability_zones)
    domain = "vpc"

    tags = {
        Name = "${var.vpc_name}-NAT-EIP-${count.index + 1}"
    }
}
resource "aws_nat_gateway" "this" {
    count = length(var.availability_zones)

    allocation_id = aws_eip.nat[count.index].id
    subnet_id = aws_subnet.public[count.index].id

    tags = {
        Name = "${var.vpc_name}-NAT-${count.index + 1}"
    }
    
    depends_on = [ aws_internet_gateway.this ]
}

# Private Routing Table 생성
resource "aws_route_table" "private" {
    count = length(var.availability_zones)

    vpc_id = aws_vpc.this.id

    route {
        cidr_block = "0.0.0.0/0"
        nat_gateway_id = aws_nat_gateway.this[count.index].id
    }

    tags = {
        Name = "${var.vpc_name}-Private-RT-${count.index + 1}"
    }
}
resource "aws_route_table_association" "private" {
    count = length(var.availability_zones)

    subnet_id = aws_subnet.private[count.index].id
    route_table_id = aws_route_table.private[count.index].id
}