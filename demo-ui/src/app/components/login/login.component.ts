import { Component, OnInit } from '@angular/core';
import { LoginService } from 'src/app/services/login.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {

  constructor(private service:LoginService) { }

  ngOnInit(): void {
    this.getMessage();
  }

  getMessage(){
    this.service.getMessage().subscribe(

      data => {console.log(data);}
    )
  }
}
