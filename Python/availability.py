from datetime import datetime,timedelta,date

dt = datetime.today()
dt1 = dt + timedelta(1)
dt2 = dt + timedelta(2)
dt3 = dt + timedelta(3)

if dt.isoweekday() == 1:    
    print("Monday", dt.strftime('%d-%m-%Y'), "1130AM-5PM")
    print("Tuesday", dt1.strftime('%d-%m-%Y'), "11AM-5PM")
    print("Wednesday", dt2.strftime('%d-%m-%Y'), "12-5PM")
    print("Thursday", dt3.strftime('%d-%m-%Y'), "11AM-1PM, 2PM-5PM")
elif dt.isoweekday() == 2:
    print("Tuesday", dt.strftime('%d-%m-%Y'), "11AM-5PM")
    print("Wednesday", dt1.strftime('%d-%m-%Y'), "12-5PM")
    print("Thursday", dt2.strftime('%d-%m-%Y'), "11AM-1PM, 2PM-5PM")
    monday = dt + timedelta(6)
    print("Monday", monday.strftime('%d-%m-%Y'), "1130AM-5PM")
elif dt.isoweekday() == 3:
    print("Wednesday", dt.strftime('%d-%m-%Y'), "12-5PM")
    print("Thursday ", dt1.strftime('%d-%m-%Y'), "11AM-1PM, 2PM-5PM")
    monday = dt + timedelta(5)
    tuesday = dt + timedelta(6)
    print("Monday", monday.strftime('%d-%m-%Y'), "1130AM-5PM")
    print("Tuesday", tuesday.strftime('%d-%m-%Y'), "1130AM-5PM")
elif dt.isoweekday() == 4:
    print("Thursday", dt.strftime('%d-%m-%Y'), "11AM-1PM, 2PM-5PM")
    monday = dt + timedelta(4)
    tuesday = dt + timedelta(5)
    wednesday = dt + timedelta(6)
    print("Monday", monday.strftime('%d-%m-%Y'), "1130AM-5PM")
    print("Tuesday", tuesday.strftime('%d-%m-%Y'), "1130AM-5PM")
    print("Wednesday", wednesday.strftime('%d-%m-%Y'), "1130AM-5PM")
