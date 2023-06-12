# FedUp-Generator

FedUp generator is used to generate an API client from the data extracted by FedUp-Extract.

In theory you can use the raw extracted data to generate an API client on your own, but a standard GraphQL client
wouldn't have the required mechanism to handle the authentication and authorization required by the Reddit API.