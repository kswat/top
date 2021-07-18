import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';//or /Observables

const httpOptions = {
  headers: new HttpHeaders({
    'Content-Type':  'application/json'

  })
};
//Authorization: 'my-auth-token' was having this after content type
@Injectable({
  providedIn: 'root'
})
export class LoginService {

  private usersUrl: string;

  constructor(private http:HttpClient) {
    // this.usersUrl = 'http://localhost:8080/loginSuccess';
    // this.usersUrl = 'http://localhost:8080/oauthlogin';
    this.usersUrl = '/uilogin';
   }

  getMessage(){
    return this.http.get<any>(this.usersUrl);
  }
}

