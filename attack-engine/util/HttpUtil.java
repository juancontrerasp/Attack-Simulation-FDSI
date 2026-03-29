package util;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class HttpUtil {

    private static final HttpClient client = HttpClient.newHttpClient();

    public static String post(String url, String json) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());

            return response.body();

        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }

    public static String get(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());

            // Include headers in response for security header checks
            StringBuilder fullResponse = new StringBuilder();
            response.headers().map().forEach((k, v) -> {
                fullResponse.append(k).append(": ").append(String.join(", ", v)).append("\n");
            });
            fullResponse.append("\n").append(response.body());

            return fullResponse.toString();

        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }

    public static String getWithAuth(String url, String token) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + token)
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());

            return response.statusCode() + " " + response.body();

        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }

    public static String getWithOrigin(String url, String origin) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Origin", origin)
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());

            // Include response headers to check CORS headers
            StringBuilder fullResponse = new StringBuilder();
            response.headers().map().forEach((k, v) -> {
                fullResponse.append(k).append(": ").append(String.join(", ", v)).append("\n");
            });
            fullResponse.append("\n").append(response.body());

            return fullResponse.toString();

        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
}