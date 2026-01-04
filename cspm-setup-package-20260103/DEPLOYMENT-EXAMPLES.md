# Deployment Examples

## AWS Console Deployment

1. Download `acquired-entity-oidc-setup.yaml`
2. Go to CloudFormation Console
3. Create Stack → Upload Template
4. Configure parameters:
   - Stack name: `csmp-oidc-setup`
   - GitHub Organization: `vibhoragarwal81`
   - GitHub Repository: `Github-Copilot`
   - Organization Name: `[Your Company]`

## AWS CLI Deployment

```bash
aws cloudformation create-stack \
  --stack-name csmp-oidc-setup \
  --template-body file://acquired-entity-oidc-setup.yaml \
  --parameters \
    ParameterKey=GitHubOrganization,ParameterValue=vibhoragarwal81 \
    ParameterKey=GitHubRepository,ParameterValue=Github-Copilot \
    ParameterKey=OrganizationName,ParameterValue="YourCompanyName" \
  --capabilities CAPABILITY_NAMED_IAM
```

## Get Role ARN

```bash
aws cloudformation describe-stacks \
  --stack-name csmp-oidc-setup \
  --query 'Stacks[0].Outputs[?OutputKey==`RoleARNForGitHub`].OutputValue' \
  --output text
```

## Cleanup

```bash
aws cloudformation delete-stack --stack-name csmp-oidc-setup
```
