package app;

import java.net.URL;
import org.springframework.web.client.RestTemplate;

public class SsrfClient {
  void fetch(RestTemplate restTemplate, String target) throws Exception {
    new URL(target).openConnection();
    restTemplate.getForObject(target, String.class);
  }
}
