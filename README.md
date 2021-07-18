# top

Angular runs on 4200

Spring boot on 8080

top project includes demo, demo-ui

Run:
./gradlew bootRun

Test page
http://localhost:8080/

Click on link on the webpage

Note: The client and secret should be updated with yours in oauth properties file
 Google Cloud IAM settings 
 
 
 Error: CORS error
 
 Access to XMLHttpRequest at 'https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=YOUR.apps.googleusercontent.com&scope=openid%20profile%20email&state=1IUao6H9BKn_TiWww%3D&redirect_uri=http://localhost:8080/login/oauth2/code/google&nonce=HDWbOuoQnXoO-6D6sVq1MVGfXS4' (redirected from 'http://localhost:8080/uilogin') from origin 'http://localhost:8080' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource.
