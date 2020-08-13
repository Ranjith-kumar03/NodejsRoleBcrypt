import { Component, OnInit } from '@angular/core';
import {EventService} from "../event.service";
import {Authservice} from "../authservice.service";

@Component({
  selector: 'app-events',
  templateUrl: './events.component.html',
  styleUrls: ['./events.component.css']
})
export class EventsComponent implements OnInit {
  events = []
  constructor(private eventService: EventService , public authService: Authservice) {

  }

  ngOnInit(): void {
    this.refresh()
  }

  deleteEvent(id)
    {
      this.eventService.deleteEvent(id).subscribe((res)=>{

        console.log(res)
        this.events = res

      } , (err) => { console.log(err)})
    }

refresh()
{
  console.log(this.authService.admin)
  this.eventService.getEvents().subscribe((res)=>{

    this.events = res
    console.log(this.events), (err) => { console.log(err)}
  })
}
}
