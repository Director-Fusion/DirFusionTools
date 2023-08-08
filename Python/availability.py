from datetime import datetime,timedelta,date

dt = datetime.today()
dt1 = dt + timedelta(1)
dt2 = dt + timedelta(2)
dt3 = dt + timedelta(3)

if dt.isoweekday() == 1:    
    monday = dt + timedelta(7)
    print("Tuesday", dt1.strftime('%d-%m-%Y'), "11AM-5PM EST")
    print("Wednesday", dt2.strftime('%d-%m-%Y'), "12-5PM EST")
    print("Thursday", dt3.strftime('%d-%m-%Y'), "11AM-1PM, 2PM-5PM EST")
    print("Monday", monday.strftime('%d-%m-%Y'), "1130AM-5PM EST")
elif dt.isoweekday() == 2:
    print("Wednesday", dt1.strftime('%d-%m-%Y'), "12-5PM EST")
    print("Thursday", dt2.strftime('%d-%m-%Y'), "11AM-1PM, 2PM-5PM EST")
    monday = dt + timedelta(6)
    tuesday = dt + timedelta(7)
    print("Monday", monday.strftime('%d-%m-%Y'), "1130AM-5PM EST")
    print("Tuesday", tuesday.strftime('%d-%m-%Y'), "11AM-5PM EST")
elif dt.isoweekday() == 3:
    print("Thursday ", dt1.strftime('%d-%m-%Y'), "11AM-1PM, 2PM-5PM EST")
    monday = dt + timedelta(5)
    tuesday = dt + timedelta(6)
    wednesday = dt + timedelta(7)
    print("Monday", monday.strftime('%d-%m-%Y'), "1130AM-5PM EST")
    print("Tuesday", tuesday.strftime('%d-%m-%Y'), "1130AM-5PM EST")
    print("Wednesday", wednesday.strftime('%d-%m-%Y'), "12-5PM EST")
elif dt.isoweekday() == 4:
    monday = dt + timedelta(4)
    tuesday = dt + timedelta(5)
    wednesday = dt + timedelta(6)
    thursday = dt + timedelta(7)
    print("Monday", monday.strftime('%d-%m-%Y'), "1130AM-5PM EST")
    print("Tuesday", tuesday.strftime('%d-%m-%Y'), "1130AM-5PM EST")
    print("Wednesday", wednesday.strftime('%d-%m-%Y'), "1130AM-5PM EST")
    print("Thursday", thursday.strftime('%d-%m-%Y'), "11AM-1PM, 2PM-5PM EST")
