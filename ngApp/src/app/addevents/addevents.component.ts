import { Component, OnInit } from '@angular/core';
import {EventService} from "../event.service";
import {Router} from "@angular/router";

@Component({
  selector: 'app-addevents',
  templateUrl: './addevents.component.html',
  styleUrls: ['./addevents.component.css']
})
export class AddeventsComponent implements OnInit {

  constructor(private eventService: EventService , private router: Router) { }

  ngOnInit(): void {
  }
  addEventsData = {
    "name" : '',
    "description": '',
    'date':''
  }

  addEvents(){
     this.addEventsData.date = new Date().toISOString()
    console.log(this.addEventsData)
   this.eventService.addEvents(this.addEventsData).subscribe((res)=>{
      console.log(res)
       this.addEventsData.name = ''
       this.addEventsData.description = ''
       this.addEventsData.date = ''
this.router.navigate(['/events'])

     }

        , (err) => { console.log(err)})

  }
}
