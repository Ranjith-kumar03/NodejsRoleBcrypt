import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import {EventsComponent} from "./events/events.component";
import {SpecialEventsComponent} from "./special-events/special-events.component";
import {LoginComponent} from "./login/login.component";
import {RegisterComponent} from "./register/register.component";
import {RegisteradminComponent} from "./registeradmin/registeradmin.component";
import {AuthGuard} from "./auth.guard";
import {AdminauthGuard} from "./adminauth.guard";
import {AddeventsComponent} from "./addevents/addevents.component";


const routes: Routes = [
  {
  path: '',
  redirectTo: '/events',
  pathMatch: 'full'
},
  {
    path: 'events',
    component: EventsComponent
  },

  {
    path: 'addevents',
    component: AddeventsComponent , canActivate: [AdminauthGuard]
  },
  {
    path: 'special',

    component: SpecialEventsComponent , canActivate: [AuthGuard]
  },
  {
    path: 'login',
    component: LoginComponent
  },

  {
    path: 'createAdmin',
    component: RegisteradminComponent , canActivate: [AdminauthGuard]
  },
  {
    path: 'register',
    component: RegisterComponent
  }];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
