import { Injectable } from '@angular/core';
import {CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, UrlTree, Router} from '@angular/router';
import { Observable } from 'rxjs';
import {Authservice} from "./authservice.service";

@Injectable({
  providedIn: 'root'
})
export class AdminauthGuard implements CanActivate {
  constructor(private authService: Authservice , private router: Router) {
  }
  canActivate(    ): boolean
  {
    if(this.authService.admin)
    {
      return true
    }else {
      this.router.navigate(['/login'])
      return false
    }
  }

}
