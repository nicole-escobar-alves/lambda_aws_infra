import boto3
import json
import os
import hmac
import hashlib
import base64

def calculate_secret_hash(client_id, client_secret, username):
    message = username + client_id
    dig = hmac.new(
        bytes(client_secret, 'utf-8'),
        msg=bytes(message, 'utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def lambda_handler(event, context):
    # Configurações do Cognito
    client_id = os.environ['COGNITO_CLIENT_ID']  # ID do App Client
    client_secret = os.environ['COGNITO_CLIENT_SECRET']
    user_pool_id = os.environ['COGNITO_USER_POOL_ID']  # ID do User Pool

    # Parse do corpo da requisição
    try:
        body = json.loads(event.get("body"))  # Converte body de string para JSON
        username = body.get('username')
        password = body.get('password')
    except (TypeError, json.JSONDecodeError):
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "Invalid JSON format"})
        }

    if not username or not password:
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "Username and password are required"})
        }

    try:
        client = boto3.client('cognito-idp', region_name='us-east-1')

        secret_hash = calculate_secret_hash(client_id, client_secret, username)

        response = client.admin_initiate_auth(
            UserPoolId=user_pool_id,
            ClientId=client_id,
            AuthFlow='ADMIN_USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )
        
        # Retornar os tokens
        return {
            "statusCode": 200,
            "body": json.dumps({
                "access_token": response['AuthenticationResult']['AccessToken'],
                "id_token": response['AuthenticationResult']['IdToken'],
                "refresh_token": response['AuthenticationResult']['RefreshToken'],
                "expires_in": response['AuthenticationResult']['ExpiresIn'],
                "token_type": response['AuthenticationResult']['TokenType']
            })
        }
    except Exception as e:
        print(f"Erro ao conectar ao Cognito: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Internal Server Error", "error": str(e)})
        }

    