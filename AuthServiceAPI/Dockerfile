FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["AuthService/AuthService.csproj", "AuthService/"]
RUN dotnet restore "AuthService/AuthService.csproj"
COPY . .
WORKDIR "/src/AuthService"
RUN dotnet build "AuthService.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "AuthService.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Fetch secrets from Vault
ENV VAULT_ADDR=$VAULT_ADDR
ENV VAULT_TOKEN=$VAULT_TOKEN
RUN apk add --no-cache curl jq
RUN MONGO_USERNAME=$(curl -X GET -H "X-Vault-Token: $VAULT_TOKEN" $VAULT_ADDR/v1/secret/data/mongodb?version=2 | jq -r '.data.data.username') \
    && MONGO_PASSWORD=$(curl -X GET -H "X-Vault-Token: $VAULT_TOKEN" $VAULT_ADDR/v1/secret/data/mongodb?version=2 | jq -r '.data.data.password') \
    && echo "MONGO_USERNAME=$MONGO_USERNAME" >> /app/env.list \
    && echo "MONGO_PASSWORD=$MONGO_PASSWORD" >> /app/env.list

ENTRYPOINT ["dotnet", "AuthService.dll"]