import { Injectable } from '@angular/core';
import {CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, UrlTree, Router} from '@angular/router';
import { Observable } from 'rxjs';
import {Authservice} from "./authservice.service";

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  constructor(private authService: Authservice , private router: Router) {
  }

  canActivate(    ): boolean
  {
   if(this.authService.loggedIn())
   {
     return true
   }else {
     this.router.navigate(['/login'])
     return false
   }
  }

}
