using FinalApp.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FinalApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class StudentController : ControllerBase
    {
        public static List<Student> students = new List<Student>();

        //[Authorize]
        // GET: Students
        //public IActionResult Get(string strSearch)
        //{
        //    try
        //    {
        //        if (string.IsNullOrEmpty(HttpContext.Session.GetString("LoginSession")))
        //        {
        //            return BadRequest();
        //        }
        //        else
        //        {
        //            StudentList stuList = new StudentList();
        //            List<Student> obj = stuList.getStudent(string.Empty).OrderBy(x => x.FullName).ToList();
        //            //Kiểm tra xem chuỗi có dữ liệu chưa?
        //            if (!String.IsNullOrEmpty(strSearch))
        //            {
        //                obj = obj.Where(x => x.FullName.Contains(strSearch) || x.Address.Contains(strSearch)).ToList();
        //            }
        //            return Ok(obj);
        //        }

        //    }
        //    catch
        //    {
        //        return BadRequest();
        //    }
        //}

        [HttpGet]
        public IActionResult Get()
        {
            try
            {
                    StudentList stuList = new StudentList();
                    List<Student> obj = stuList.getStudent(string.Empty).OrderBy(x => x.FullName).ToList();
                    //Kiểm tra xem chuỗi có dữ liệu chưa?
                    return Ok(obj);
          
            }
            catch
            {
                return BadRequest();
            }
        }


        [HttpGet("{id}")]
        //[Authorize]
        //Detail
        public IActionResult Details(String id = "")
        {
            StudentList stuList = new StudentList();
            List<Student> obj = stuList.getStudent(id); //.OrderBy(x => x.FullName).ToList()
            if (obj != null)
            {
                return Ok(obj.FirstOrDefault());
            }
            else return NotFound();
        }


        [HttpPost]
        //[Authorize]
        //[ValidateAntiForgeryToken]
        public IActionResult Create([Bind("ID,FullName,Address,Note")] Student student)
        {
            try
            {
                var std = new Student {
                    FullName = student.FullName,
                    Address = student.Address,
                    Note = student.Note
                };
                if (ModelState.IsValid)
                {
                    StudentList stuList = new StudentList();
                    stuList.AddStudent(std);
                    return StatusCode(StatusCodes.Status201Created, std);
                }
                else return BadRequest();
            }
            catch
            {
                return BadRequest();
            }
        }

        [HttpPut("{id}")]
        //[Authorize]
        //[ValidateAntiForgeryToken]
        public IActionResult Edit(Student stu, string id = "")
        {
            StudentList stuList = new StudentList();
            List<Student> obj = stuList.getStudent(id).OrderBy(x => x.FullName).ToList();
            var student = obj.FirstOrDefault();
            if (student != null)
            {
                student.FullName = stu.FullName;
                student.Address = stu.Address;
                student.Note = stu.Note;
                stuList.UpdateStudent(student);
                return StatusCode(StatusCodes.Status204NoContent);
            }
            else return NotFound();
        }

        //Delete
        [HttpDelete("{id}")]
        //[ValidateAntiForgeryToken]
        //[Authorize]
        public IActionResult DeleteById(string id = "")
        {
            StudentList stuList = new StudentList();
            List<Student> obj = stuList.getStudent(id);
            var student = obj.FirstOrDefault();
            if (student != null)
            {
                stuList.DeleteStudent(student);
                return StatusCode(StatusCodes.Status200OK);
            }
            else
            {
                return NotFound();
            }
        }

    }
}
