type IdentityProviderId = number;

type IdentityProviderType = "OAUTH2" | "google" | "github" | "gitlab" | "oidc";

interface FieldMapping {
  identifier: string;
  displayName: string;
  email: string;
}

interface IdentityProviderOAuth2Config {
  clientId: string;
  clientSecret: string;
  authUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scopes: string[];
  fieldMapping: FieldMapping;
  instanceUrl?: string;
  provider?: string;
}

interface IdentityProviderConfig {
  oauth2Config?: IdentityProviderOAuth2Config;
  clientId?: string;
  clientSecret?: string;
  authUrl?: string;
  tokenUrl?: string;
  userInfoUrl?: string;
  scopes?: string[];
  fieldMapping?: FieldMapping;
  instanceUrl?: string;
  provider?: string;
}

interface IdentityProvider {
  id: IdentityProviderId;
  name: string;
  type: IdentityProviderType;
  identifierFilter: string;
  config: IdentityProviderConfig;
}

interface IdentityProviderCreate {
  name: string;
  type: IdentityProviderType;
  identifierFilter: string;
  config: IdentityProviderConfig;
}

interface IdentityProviderPatch {
  id: IdentityProviderId;
  type: IdentityProviderType;
  name?: string;
  identifierFilter?: string;
  config?: IdentityProviderConfig;
}
