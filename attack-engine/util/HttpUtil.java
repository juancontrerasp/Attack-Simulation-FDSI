package util;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class HttpUtil {

    private static volatile HttpClient client = newClient(5000);
    private static volatile int requestTimeoutMs = 10000;

    public static void configure(int connectTimeoutMs, int reqTimeoutMs) {
        requestTimeoutMs = reqTimeoutMs;
        client = newClient(connectTimeoutMs);
    }

    private static HttpClient newClient(int connectTimeoutMs) {
        return HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(connectTimeoutMs))
            .build();
    }

    public static String post(String url, String json) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofMillis(requestTimeoutMs))
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
                    .timeout(Duration.ofMillis(requestTimeoutMs))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());

            StringBuilder fullResponse = new StringBuilder();
            response.headers().map().forEach((k, v) ->
                fullResponse.append(k).append(": ").append(String.join(", ", v)).append("\n"));
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
                    .timeout(Duration.ofMillis(requestTimeoutMs))
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
                    .timeout(Duration.ofMillis(requestTimeoutMs))
                    .header("Origin", origin)
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());

            StringBuilder fullResponse = new StringBuilder();
            response.headers().map().forEach((k, v) ->
                fullResponse.append(k).append(": ").append(String.join(", ", v)).append("\n"));
            fullResponse.append("\n").append(response.body());

            return fullResponse.toString();

        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
}
