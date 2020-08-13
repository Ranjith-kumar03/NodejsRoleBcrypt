import { Component, OnInit } from '@angular/core';
import {Authservice} from "../authservice.service";
import {Router} from "@angular/router";

@Component({
  selector: 'app-registeradmin',
  templateUrl: './registeradmin.component.html',
  styleUrls: ['./registeradmin.component.css']
})
export class RegisteradminComponent implements OnInit {

  constructor(private authservice: Authservice , private router: Router) { }

  ngOnInit(): void {
  }
  registerAdminUserData = {
    "email": '',
    "password": '',
    "roles":"ADMIN"
  }

  registerAdmin() {
    this.authservice.registerUser(this.registerAdminUserData).subscribe((res) => {
      console.log(res)
      this.router.navigate(['/special'])
    }, (err) => {
        console.log(err)
      })
  }
}
