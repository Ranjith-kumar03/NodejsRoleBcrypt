import { Component } from '@angular/core';
import {Authservice} from "./authservice.service";
import {Router} from "@angular/router";

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {

  constructor(public authService: Authservice , private router: Router) {

  }

  loggedOut()
  {
    this.authService.logOut()
    this.router.navigateByUrl('/events')

  }
}
