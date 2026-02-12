#!/bin/bash
# cleanall.sh - Comprehensive AWS cleanup script for redStack infrastructure
# WARNING: This script will DELETE ALL resources created by this project

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}========================================${NC}"
echo -e "${RED}  redStack INFRASTRUCTURE CLEANUP SCRIPT${NC}"
echo -e "${RED}========================================${NC}"
echo ""
echo -e "${YELLOW}WARNING: This will DELETE ALL AWS resources for this project!${NC}"
echo ""
echo "This includes:"
echo "  - All EC2 instances (Mythic, Guacamole, Windows, Redirector)"
echo "  - All Elastic IPs"
echo "  - All VPCs and networking resources"
echo "  - All security groups"
echo "  - All Lambda functions and API Gateways"
echo "  - All CloudWatch log groups"
echo "  - Local Terraform state files"
echo ""
echo -e "${RED}This action CANNOT be undone!${NC}"
echo ""
read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Cleanup cancelled."
    exit 0
fi

echo ""
echo -e "${GREEN}[1/5] Running terraform destroy...${NC}"

# Try Terraform destroy first (cleanest method)
if terraform destroy -auto-approve 2>/dev/null; then
    echo -e "${GREEN}✓ Terraform destroy completed successfully${NC}"
else
    echo -e "${YELLOW}⚠ Terraform destroy failed or partially completed. Proceeding with manual cleanup...${NC}"
fi

echo ""
echo -e "${GREEN}[2/5] Cleaning up any remaining EC2 instances...${NC}"

# Get all instances with the project tag
INSTANCE_IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:Project,Values=redStack" "Name=instance-state-name,Values=running,stopped,stopping" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text 2>/dev/null || echo "")

if [ -n "$INSTANCE_IDS" ]; then
    echo "Terminating instances: $INSTANCE_IDS"
    aws ec2 terminate-instances --instance-ids $INSTANCE_IDS
    echo "Waiting for instances to terminate..."
    aws ec2 wait instance-terminated --instance-ids $INSTANCE_IDS 2>/dev/null || echo "Wait timeout (instances may still be terminating)"
    echo -e "${GREEN}✓ Instances terminated${NC}"
else
    echo -e "${GREEN}✓ No instances found${NC}"
fi

echo ""
echo -e "${GREEN}[3/5] Cleaning up Elastic IPs...${NC}"

# Release all Elastic IPs for the project
EIP_ALLOC_IDS=$(aws ec2 describe-addresses \
    --filters "Name=tag:Project,Values=redStack" \
    --query 'Addresses[].AllocationId' \
    --output text 2>/dev/null || echo "")

if [ -n "$EIP_ALLOC_IDS" ]; then
    for EIP_ID in $EIP_ALLOC_IDS; do
        echo "Releasing Elastic IP: $EIP_ID"
        aws ec2 release-address --allocation-id $EIP_ID 2>/dev/null || echo "  (already released or not found)"
    done
    echo -e "${GREEN}✓ Elastic IPs released${NC}"
else
    echo -e "${GREEN}✓ No Elastic IPs found${NC}"
fi

echo ""
echo -e "${GREEN}[4/5] Cleaning up networking resources...${NC}"

# Delete VPC peering connections
PEERING_IDS=$(aws ec2 describe-vpc-peering-connections \
    --filters "Name=tag:Project,Values=redStack" "Name=status-code,Values=active,pending-acceptance" \
    --query 'VpcPeeringConnections[].VpcPeeringConnectionId' \
    --output text 2>/dev/null || echo "")

if [ -n "$PEERING_IDS" ]; then
    for PEER_ID in $PEERING_IDS; do
        echo "Deleting VPC peering connection: $PEER_ID"
        aws ec2 delete-vpc-peering-connection --vpc-peering-connection-id $PEER_ID 2>/dev/null || echo "  (already deleted)"
    done
    echo -e "${GREEN}✓ VPC peering connections deleted${NC}"
else
    echo -e "${GREEN}✓ No VPC peering connections found${NC}"
fi

# Wait a moment for dependencies to clear
sleep 5

# Delete Lambda functions
echo "Checking for Lambda functions..."
LAMBDA_FUNCTIONS=$(aws lambda list-functions \
    --query "Functions[?starts_with(FunctionName, 'redStack') || starts_with(FunctionName, 'redteam')].FunctionName" \
    --output text 2>/dev/null || echo "")

if [ -n "$LAMBDA_FUNCTIONS" ]; then
    for FUNC in $LAMBDA_FUNCTIONS; do
        echo "Deleting Lambda function: $FUNC"
        aws lambda delete-function --function-name $FUNC 2>/dev/null || echo "  (already deleted)"
    done
    echo -e "${GREEN}✓ Lambda functions deleted${NC}"
else
    echo -e "${GREEN}✓ No Lambda functions found${NC}"
fi

# Delete API Gateways
echo "Checking for API Gateways..."
API_IDS=$(aws apigatewayv2 get-apis \
    --query "Items[?starts_with(Name, 'redStack') || starts_with(Name, 'redteam')].ApiId" \
    --output text 2>/dev/null || echo "")

if [ -n "$API_IDS" ]; then
    for API_ID in $API_IDS; do
        echo "Deleting API Gateway: $API_ID"
        aws apigatewayv2 delete-api --api-id $API_ID 2>/dev/null || echo "  (already deleted)"
    done
    echo -e "${GREEN}✓ API Gateways deleted${NC}"
else
    echo -e "${GREEN}✓ No API Gateways found${NC}"
fi

# Delete CloudWatch log groups
echo "Checking for CloudWatch log groups..."
LOG_GROUPS=$(aws logs describe-log-groups \
    --query "logGroups[?starts_with(logGroupName, '/aws/lambda/redStack') || starts_with(logGroupName, '/aws/lambda/redteam')].logGroupName" \
    --output text 2>/dev/null || echo "")

if [ -n "$LOG_GROUPS" ]; then
    for LOG_GROUP in $LOG_GROUPS; do
        echo "Deleting log group: $LOG_GROUP"
        aws logs delete-log-group --log-group-name $LOG_GROUP 2>/dev/null || echo "  (already deleted)"
    done
    echo -e "${GREEN}✓ CloudWatch log groups deleted${NC}"
else
    echo -e "${GREEN}✓ No CloudWatch log groups found${NC}"
fi

# Get all VPCs for the project
VPC_IDS=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Project,Values=redStack" \
    --query 'Vpcs[].VpcId' \
    --output text 2>/dev/null || echo "")

if [ -n "$VPC_IDS" ]; then
    for VPC_ID in $VPC_IDS; do
        echo "Cleaning up VPC: $VPC_ID"

        # Delete NAT Gateways
        NAT_IDS=$(aws ec2 describe-nat-gateways \
            --filter "Name=vpc-id,Values=$VPC_ID" "Name=state,Values=available" \
            --query 'NatGateways[].NatGatewayId' \
            --output text 2>/dev/null || echo "")

        if [ -n "$NAT_IDS" ]; then
            for NAT_ID in $NAT_IDS; do
                echo "  Deleting NAT Gateway: $NAT_ID"
                aws ec2 delete-nat-gateway --nat-gateway-id $NAT_ID 2>/dev/null || echo "    (already deleted)"
            done
        fi

        # Delete Internet Gateways
        IGW_IDS=$(aws ec2 describe-internet-gateways \
            --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
            --query 'InternetGateways[].InternetGatewayId' \
            --output text 2>/dev/null || echo "")

        if [ -n "$IGW_IDS" ]; then
            for IGW_ID in $IGW_IDS; do
                echo "  Detaching and deleting Internet Gateway: $IGW_ID"
                aws ec2 detach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID 2>/dev/null || echo "    (already detached)"
                aws ec2 delete-internet-gateway --internet-gateway-id $IGW_ID 2>/dev/null || echo "    (already deleted)"
            done
        fi

        # Delete Subnets
        SUBNET_IDS=$(aws ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$VPC_ID" \
            --query 'Subnets[].SubnetId' \
            --output text 2>/dev/null || echo "")

        if [ -n "$SUBNET_IDS" ]; then
            for SUBNET_ID in $SUBNET_IDS; do
                echo "  Deleting Subnet: $SUBNET_ID"
                aws ec2 delete-subnet --subnet-id $SUBNET_ID 2>/dev/null || echo "    (already deleted)"
            done
        fi

        # Delete Route Tables (except main)
        ROUTE_TABLE_IDS=$(aws ec2 describe-route-tables \
            --filters "Name=vpc-id,Values=$VPC_ID" \
            --query 'RouteTables[?Associations[0].Main==`false`].RouteTableId' \
            --output text 2>/dev/null || echo "")

        if [ -n "$ROUTE_TABLE_IDS" ]; then
            for RT_ID in $ROUTE_TABLE_IDS; do
                echo "  Deleting Route Table: $RT_ID"
                aws ec2 delete-route-table --route-table-id $RT_ID 2>/dev/null || echo "    (already deleted)"
            done
        fi

        # Delete Security Groups (except default)
        SG_IDS=$(aws ec2 describe-security-groups \
            --filters "Name=vpc-id,Values=$VPC_ID" \
            --query 'SecurityGroups[?GroupName!=`default`].GroupId' \
            --output text 2>/dev/null || echo "")

        if [ -n "$SG_IDS" ]; then
            echo "  Deleting Security Groups..."
            # Need to delete in multiple passes due to dependencies
            for i in {1..3}; do
                for SG_ID in $SG_IDS; do
                    aws ec2 delete-security-group --group-id $SG_ID 2>/dev/null && echo "    Deleted: $SG_ID" || true
                done
                sleep 2
            done
        fi

        # Delete VPC
        echo "  Deleting VPC: $VPC_ID"
        aws ec2 delete-vpc --vpc-id $VPC_ID 2>/dev/null || echo "    (already deleted or has dependencies)"
    done
    echo -e "${GREEN}✓ VPC resources cleaned up${NC}"
else
    echo -e "${GREEN}✓ No project VPCs found${NC}"
fi

# Delete any remaining ENIs
echo "Checking for remaining Network Interfaces..."
ENI_IDS=$(aws ec2 describe-network-interfaces \
    --filters "Name=tag:Project,Values=redStack" \
    --query 'NetworkInterfaces[].NetworkInterfaceId' \
    --output text 2>/dev/null || echo "")

if [ -n "$ENI_IDS" ]; then
    for ENI_ID in $ENI_IDS; do
        echo "Deleting Network Interface: $ENI_ID"
        aws ec2 delete-network-interface --network-interface-id $ENI_ID 2>/dev/null || echo "  (in use or already deleted)"
    done
    echo -e "${GREEN}✓ Network interfaces deleted${NC}"
else
    echo -e "${GREEN}✓ No network interfaces found${NC}"
fi

echo ""
echo -e "${GREEN}[5/5] Cleaning up local Terraform state...${NC}"

# Remove Lambda from state (if it exists)
terraform state rm aws_lambda_function.redirector 2>/dev/null || true
terraform state rm aws_security_group.lambda_redirector 2>/dev/null || true
terraform state rm aws_security_group_rule.lambda_egress 2>/dev/null || true
terraform state rm aws_security_group_rule.mythic_from_lambda 2>/dev/null || true
terraform state rm aws_iam_role.lambda_redirector_role 2>/dev/null || true
terraform state rm aws_iam_role_policy_attachment.lambda_basic_execution 2>/dev/null || true
terraform state rm aws_iam_role_policy_attachment.lambda_vpc_execution 2>/dev/null || true
terraform state rm aws_cloudwatch_log_group.lambda_redirector 2>/dev/null || true
terraform state rm aws_apigatewayv2_api.lambda_redirector 2>/dev/null || true
terraform state rm aws_apigatewayv2_integration.lambda_redirector 2>/dev/null || true
terraform state rm aws_apigatewayv2_route.lambda_redirector 2>/dev/null || true
terraform state rm aws_apigatewayv2_stage.lambda_redirector 2>/dev/null || true
terraform state rm aws_lambda_permission.api_gateway 2>/dev/null || true

# Clean local files
rm -f lambda_function.zip
rm -f terraform.tfstate terraform.tfstate.backup
rm -rf .terraform/terraform.tfstate

echo -e "${GREEN}✓ Local state cleaned${NC}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}     CLEANUP COMPLETE!                 ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "All AWS resources for the redStack project have been deleted."
echo ""
echo "Note: Some resources (like ENIs, NAT Gateways) may take 10-15 minutes"
echo "to fully delete in AWS. If you see errors on re-deployment, wait a"
echo "few minutes and try again."
echo ""
echo "To start fresh deployment:"
echo "  terraform init"
echo "  terraform plan"
echo "  terraform apply"
echo ""
