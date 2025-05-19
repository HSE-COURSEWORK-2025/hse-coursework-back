import logging
from typing import List
from fastapi import APIRouter, HTTPException, Request, Depends, status
import httpx
from app.settings import settings
from app.services.findDataOutliers import analyze_and_return_json, generate_random_data
from app.models.getData import DataElementSchema, DataType, AnalyzedDataSchema

logger = logging.getLogger("get_data_routers")
api_v2_get_data_router = APIRouter(prefix="/getData")


# Заменённый эндпоинт проверки токена через внешний сервис авторизации
async def get_current_user(request: Request):
    logger.info("Authentication attempt from %s", request.client.host if request.client else "unknown")
    auth_header = request.headers.get("Authorization")
    if auth_header is None:
        logger.warning("Missing Authorization header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.warning("Invalid Authorization header format: %s", auth_header)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
        )
    token = parts[1]
    logger.debug("Token extracted: %s", token[:8] + "..." if len(token) > 8 else token)

    # Запрос к сервису авторизации
    try:
        logger.info("Requesting user info from auth service: %s", settings.AUTH_API_URL)
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.get(
                f"{settings.AUTH_API_URL}/auth-api/api/v1/auth/users/me",
                headers={
                    "accept": "application/json",
                    "Authorization": f"Bearer {token}",
                },
            )
    except httpx.RequestError as exc:
        logger.error("Error while requesting authentication service: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service unavailable",
        )

    if response.status_code != 200:
        logger.error("Token validation failed with status %s, response: %s", response.status_code, response.text)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    try:
        user_data = response.json()
        logger.info("User authenticated: %s", user_data.get("email", "unknown"))
    except Exception as e:
        logger.error("Error parsing authentication response: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error",
        )
    return user_data


# Эндпоинт для получения сырых данных
@api_v2_get_data_router.get(
    "/getRawData",
    status_code=200,
    response_model=List[DataElementSchema],
    tags=["get_data"],
)
async def getRawData(
    data_type: DataType, current_user: dict = Depends(get_current_user)
) -> List[DataElementSchema]:
    logger.info("User %s requested raw data for type %s", current_user.get("email", "unknown"), data_type)
    try:
        generated_data = generate_random_data(data_type)
        logger.debug("Generated %d data points for type %s", len(generated_data), data_type)
        return generated_data
    except Exception as e:
        logger.error(f"Error generating data: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Эндпоинт для получения обработанных (анализированных) данных
@api_v2_get_data_router.get(
    "/getAnalyzedData",
    status_code=200,
    response_model=AnalyzedDataSchema,
    tags=["get_data"],
)
async def getAnalyzedData(
    data_type: DataType, current_user: dict = Depends(get_current_user)
) -> AnalyzedDataSchema:
    logger.info("User %s requested analyzed data for type %s", current_user.get("email", "unknown"), data_type)
    try:
        generated_data = generate_random_data(data_type)
        logger.debug("Generated %d data points for analysis for type %s", len(generated_data), data_type)
        result = analyze_and_return_json(generated_data)
        logger.debug("Analysis result: %d outliers found", len(result.get("outliersX", [])))
        return AnalyzedDataSchema.model_validate(result)
    except Exception as e:
        logger.error(f"Error analyzing data: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
