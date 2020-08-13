import { Component, OnInit } from '@angular/core';
import {Authservice} from "../authservice.service";
import {Router} from "@angular/router";

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {

  registerUserData = {
    "email": "",
    "password": ""
  }

  constructor(private authservice: Authservice  , private router: Router) { }

  ngOnInit(): void {
  }
  registerUser()
  {
   this.authservice.registerUser(this.registerUserData).subscribe((res)=>{
     console.log(res.accessToken)
     localStorage.setItem('token', res.accessToken)
       this.router.navigate(['/special'])}
       , (err) => { console.log(err)})
  }
}
