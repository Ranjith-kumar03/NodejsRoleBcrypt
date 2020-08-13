import { Component, OnInit } from '@angular/core';
import {Authservice} from "../authservice.service";
import {Router} from "@angular/router";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  loginUserData = {
    "email":'',
    "password":''
  }
  constructor(private authservice: Authservice , private router: Router) { }

  ngOnInit(): void {
  }
  loginUser()
  {
  this.authservice.loginUser(this.loginUserData).subscribe((res)=>{
    console.log(res.accessToken)
    localStorage.setItem('token', res.accessToken)
    this.router.navigate(['/special'])  , (err) => { console.log(err)}
  })
  }

}
