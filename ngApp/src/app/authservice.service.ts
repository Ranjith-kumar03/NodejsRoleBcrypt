import { Injectable } from '@angular/core';
import {HttpClient, HttpErrorResponse} from "@angular/common/http";
import {Observable, throwError} from "rxjs";
import {catchError} from "rxjs/operators";

@Injectable({
  providedIn: 'root'
})
export class Authservice {

    private _registerUrl = 'http://localhost:3000/api/register'
    private _loginUrl = 'http://localhost:3000/api/login'
    public admin


  constructor(private http: HttpClient) { }

  registerUser(user): Observable<any>
  {
    return this.http.post<any>(this._registerUrl , user).pipe(catchError(this.errorHandler))
  }

  loginUser(user): Observable<any>
  {
   var status = this.http.post<any>(this._loginUrl , user).pipe(catchError(this.errorHandler))
    this.isAdmin(status);
    return this.http.post<any>(this._loginUrl , user).pipe(catchError(this.errorHandler))
  }

  errorHandler(err: HttpErrorResponse)
  {
    return throwError(err || 'server error')
  }
  isAdmin(status)
  {
    status.subscribe((res)=>{
      if(res.roles==='ADMIN')
      {
       this.admin = true
      }else {
       this.admin = false;
      }
      console.log(this.admin)
      console.log(res), (err) => { console.log(err)}
    })
  }

  loggedIn()
  {
    return !!localStorage.getItem('token')
  }

  getToken(): any
  {
    return localStorage.getItem('token')
  }
  getRole()
  {

  }

  logOut()
  {
    localStorage.removeItem('token')
  }

}
