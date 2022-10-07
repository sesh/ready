from ready.result import result
from ready.thttp import request


# WIP: GraphQL introspection should not be enabled (requires --fuzz)
def check_graphql_introspection_should_not_be_enabled(requests, **kwargs):
    # https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL#introspection-queries
    # https://the-bilal-rizwan.medium.com/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696
    paths = [
        "graphql"
        "api"
        "api/graphql"
        "api/graphiql"
        "graphiql"
        "v1/graphql"
        "v2/graphql"
        "v3/graphql"
        "v1/graphiql"
        "v2/graphiql"
        "v3/graphiql"
        "console"
        "playground"
        "gql"
        "index.php%3Fgraphql"
        "graphql/"
        "api/"
        "api/graphql/"
        "api/graphiql/"
        "graphiql/"
        "v1/graphql/"
        "v2/graphql/"
        "v3/graphql/"
        "v1/graphiql/"
        "v2/graphiql/"
        "v3/graphiql/"
        "console/"
        "playground/"
        "gql"
    ]
