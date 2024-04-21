# Define the API endpoint URL and the bearer token
$endpointUrl = "http://a935-41-233-211-77.ngrok-free.app/tasks/view/17"
$bearerToken = "wJJR0WHus5-J0a5HClHnCA"

# Construct the headers as a hashtable
$headers = @{
    "Authorization" = "Bearer $bearerToken"
}

# Make the HTTP GET request using Invoke-WebRequest
try {
    $response = Invoke-WebRequest -Uri $endpointUrl -Headers $headers -Method Get
    # Check the HTTP status code of the response
    if ($response.StatusCode -eq 200) {
        # If the request is successful (HTTP status code 200), output the content
        Write-Output $response.Content
    } else {
        # If the request fails, display the status code and status description
        Write-Error "Request failed with status code $($response.StatusCode): $($response.StatusDescription)"
    }
} catch {
    # Catch any errors that occur during the request
    Write-Error "An error occurred: $_"
}
