import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { RegisterComponent } from './register/register.component';
import { LoginComponent } from './login/login.component';
import { EventsComponent } from './events/events.component';
import { SpecialEventsComponent } from './special-events/special-events.component';
import {FormsModule} from "@angular/forms";
import {HTTP_INTERCEPTORS, HttpClientModule} from "@angular/common/http";
import {Authservice} from "./authservice.service";
import { RegisteradminComponent } from './registeradmin/registeradmin.component';
import {EventService} from "./event.service";
import {AuthGuard} from "./auth.guard";
import {AdminauthGuard} from "./adminauth.guard";
import {TokenInterceptorService} from "./token-interceptor.service";
import { AddeventsComponent } from './addevents/addevents.component';

@NgModule({
  declarations: [
    AppComponent,
    RegisterComponent,
    LoginComponent,
    EventsComponent,
    SpecialEventsComponent,
    RegisteradminComponent,
    AddeventsComponent
  ],
  imports: [
    BrowserModule,
    HttpClientModule ,
    FormsModule ,
    AppRoutingModule

  ],
  providers: [Authservice , EventService ,AuthGuard , AdminauthGuard,{
    provide : HTTP_INTERCEPTORS,
    useClass : TokenInterceptorService,
    multi: true
  }],
  bootstrap: [AppComponent]
})
export class AppModule { }
