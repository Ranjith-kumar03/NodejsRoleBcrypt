import { Injectable } from '@angular/core';
import {HttpClient, HttpErrorResponse} from "@angular/common/http";
import {Observable, throwError} from "rxjs";
import {catchError} from "rxjs/operators";

@Injectable({
  providedIn: 'root'
})
export class EventService {
  private _eventsURL = 'http://localhost:3000/api/events'
  private _specialURL = 'http://localhost:3000/api/special'
  private _addEventsURL = 'http://localhost:3000/api/events'
  private _deletEventsURL = 'http://localhost:3000/api/event/'

  constructor(private http: HttpClient) { }

  getEvents(): Observable<any>
  {
    return this.http.get<any>(this._eventsURL).pipe(catchError(this.errorHandler))
  }

  getSpecialEvents(): Observable<any>
  {
    return this.http.get<any>(this._specialURL).pipe(catchError(this.errorHandler))
  }

  addEvents(event)
  {
    return this.http.post(this._addEventsURL , event).pipe(catchError(this.errorHandler))
  }

  deleteEvent(id): Observable<any>
  {
    return this.http.delete(this._deletEventsURL+id).pipe(catchError(this.errorHandler))
  }

  errorHandler(err: HttpErrorResponse)
  {
    return throwError(err || 'server error')
  }
}
