# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import logging
import os
import threading
from typing import Any, Optional, cast

from azure.core.credentials import AccessToken, AccessTokenInfo, TokenRequestOptions, SupportsTokenInfo
from .. import CredentialUnavailableError
from .client_assertion import ClientAssertionCredential
from .managed_identity import ManagedIdentityCredential
from .._constants import EnvironmentVariables
from .._internal import get_default_authority, normalize_authority

_LOGGER = logging.getLogger(__name__)


class AzureFederatedIdentityCredential:
    """A credential for An Azure Federated Identity (Manged Identity mapped to an app registration).

    This credential is designed for applications deployed to Azure whow want to auth across tenant boudaries.
    (:class:`~azure.identity.DefaultAzureCredential` is better suited to local development).
    
    It authenticates a managed identity to an app registration in a different tenant.

    For service principal authentication, set these environment variables to identify a principal:

        - **AZURE_FEDERATED_APPLICATION_ID**: ID of the app registration in the tenant where the managed identity is
        - **AZURE_CLIENT_ID**: ID of the managed identity if using user assigned managed identies

    :keyword str authority: Authority of a Microsoft Entra endpoint, for example "login.microsoftonline.com",
        the authority for Azure Public Cloud, which is the default when no value is given for this keyword argument or
        environment variable AZURE_AUTHORITY_HOST. :class:`~azure.identity.AzureAuthorityHosts` defines authorities for
        other clouds. Authority configuration applies only to service principal authentication.
    :keyword str managed_identity_client_id: The client ID of a user-assigned managed identity. Defaults to the value
        of the environment variable AZURE_CLIENT_ID, if any. If not specified, a system-assigned identity will be used.
    """

    OIDC_SCOPE = "api://AzureADTokenExchange/.default"

    def __init__(self, **kwargs: Any) -> None:
        authority = kwargs.get("authority", None)
        authority = normalize_authority(authority) if authority else get_default_authority()
        managed_identity_client_id = kwargs.get(
            "managed_identity_client_id", os.environ.get(EnvironmentVariables.AZURE_CLIENT_ID)
        )
        self.federated_application_id : str = os.environ.get(EnvironmentVariables.AZURE_FEDERATED_APPLICATION_ID) or ""
        self.managed_identity_client = ManagedIdentityCredential(client_id=managed_identity_client_id)
        self.client_assertion_credentials: dict[str, ClientAssertionCredential] = {}
        self._lock = threading.Lock()

    def get_token(
        self, *scopes: str, claims: Optional[str] = None, tenant_id: Optional[str] = None, **kwargs: Any
    ) -> AccessToken:
        """Request an access token for `scopes`.

        This method is called automatically by Azure SDK clients.

        :param str scopes: desired scopes for the access token. This method requires at least one scope.
            For more information about scopes, see
            https://learn.microsoft.com/entra/identity-platform/scopes-oidc.
        :keyword str claims: additional claims required in the token, such as those returned in a resource provider's
            claims challenge following an authorization failure.
        :keyword str tenant_id: optional tenant to include in the token request.

        :return: An access token with the desired scopes.
        :rtype: ~azure.core.credentials.AccessToken
        :raises ~azure.core.exceptions.ClientAuthenticationError: authentication failed. The exception has a
            `message` attribute listing each authentication attempt and its error message.
        """

        if not tenant_id:
            raise CredentialUnavailableError(message="tenant_id must be specified")
    
        with self._lock:
            if tenant_id not in self.client_assertion_credentials:
                self.client_assertion_credentials[tenant_id] = ClientAssertionCredential(tenant_id=tenant_id or "", client_id=self.federated_application_id, func=lambda *args, **kwargs: self.managed_identity_client.get_token(*AzureFederatedIdentityCredential.OIDC_SCOPE, None, None, **kwargs))
        return self.client_assertion_credentials[tenant_id].get_token(*scopes, claims=claims, tenant_id=tenant_id, **kwargs)
    
    def get_token_info(self, *scopes: str, options: Optional[TokenRequestOptions] = None) -> AccessTokenInfo:
        """Request an access token for `scopes`.

        This is an alternative to `get_token` to enable certain scenarios that require additional properties
        on the token. This method is called automatically by Azure SDK clients.

        :param str scopes: desired scope for the access token. This method requires at least one scope.
            For more information about scopes, see https://learn.microsoft.com/entra/identity-platform/scopes-oidc.
        :keyword options: A dictionary of options for the token request. Unknown options will be ignored. Optional.
        :paramtype options: ~azure.core.credentials.TokenRequestOptions

        :rtype: AccessTokenInfo
        :return: An AccessTokenInfo instance containing information about the token.

        :raises ~azure.identity.CredentialUnavailableError: environment variable configuration is incomplete.
        """
        if not options:
            raise CredentialUnavailableError(message="tenant_id must be specified in TokenRequestOptions")

        tenant_id : str = options.get("tenant_id", None)

        if not tenant_id:
            raise CredentialUnavailableError(message="tenant_id must be specified")

        with self._lock:
            if tenant_id not in self.client_assertion_credentials:
                self.client_assertion_credentials[tenant_id] = ClientAssertionCredential(tenant_id=tenant_id,client_id=self.federated_application_id,func=lambda *args, **kwargs: self.managed_identity_client.get_token(*AzureFederatedIdentityCredential.OIDC_SCOPE,None,None,**kwargs))

        return cast(SupportsTokenInfo, self.client_assertion_credentials[tenant_id]).get_token_info(*scopes, options=options)
    