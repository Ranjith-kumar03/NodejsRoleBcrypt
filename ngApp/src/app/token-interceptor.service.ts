import { Injectable } from '@angular/core';
import {HttpHandler, HttpInterceptor, HttpRequest} from "@angular/common/http";
import {Authservice} from "./authservice.service";

@Injectable({
  providedIn: 'root'
})
export class TokenInterceptorService implements HttpInterceptor{

  constructor(private authService: Authservice ) { }

  intercept(req: HttpRequest<any>, next: HttpHandler)
  {
   let tokenizedRequest = req.clone({
     setHeaders: {
       Authorization: `Bearer ${this.authService.getToken()}`
     }
   })
    return next.handle(tokenizedRequest)
  }
}
