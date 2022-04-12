using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;

namespace FinalApp.Models
{
    public class Student
    {
        public int ID { set; get; }
        [Required(ErrorMessage = "Mời nhập Họ và tên sinh viên")]
        [Display(Name = "Họ và tên:")]
        public string FullName { set; get; }
        [Required(ErrorMessage = "Mời nhập địa chỉ")]
        [Display(Name = "Địa chỉ:")]
        public string Address { set; get; }
        //[Required(ErrorMessage = "Mời nhập chú thích cho sinh viên")]
        [Display(Name = "Ghi chú:")]
        public string Note { set; get; }
    }
    class StudentList
    {

        private readonly IConfiguration _configuration;
        string connectStr = @"data source = NTTRUNG1; database = StudentsManagement; Integrated Security=true";

        public StudentList(IConfiguration configuration)
        {
            this._configuration = configuration;
        }

        public StudentList()
        {
        }
        //Lay ra danh sach Student theo ID va hien thi
        public List<Student> getStudent(string ID)
        {

            string sql;
            if (string.IsNullOrEmpty(ID))
                sql = "SELECT * FROM Students";
            else
                sql = "SELECT * FROM Students WHERE ID = " + ID;

            List<Student> stuList = new List<Student>();
            DataTable dt = new DataTable();

            //using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
            using (SqlConnection sqlConnection = new SqlConnection(connectStr))
            {
                SqlDataAdapter da = new SqlDataAdapter(sql, sqlConnection);
                sqlConnection.Open();
                da.Fill(dt); //Do du lieu vao data table
                da.Dispose(); //Đóng command
                sqlConnection.Close(); // huy ket noi database
            }


            Student tmpStu;
            for (int i = 0; i < dt.Rows.Count; i++)
            {
                tmpStu = new Student();
                tmpStu.ID = Convert.ToInt32(dt.Rows[i]["ID"].ToString());
                tmpStu.FullName = dt.Rows[i]["Fullname"].ToString();
                tmpStu.Address = dt.Rows[i]["Address"].ToString();
                tmpStu.Note = dt.Rows[i]["Note"].ToString();
                stuList.Add(tmpStu);
            }
            return stuList;

        }

        //Them sinh vien
        public void AddStudent(Student stu)
        {
            string sql = "INSERT INTO Students(fullname, address, note) VALUES(N'" + stu.FullName
                + "', N'" + stu.Address + "', N'" + stu.Note + "')";
            SqlConnection con = new SqlConnection(connectStr);
            SqlCommand cmd = new SqlCommand(sql, con);
            con.Open();
            cmd.ExecuteNonQuery();
            cmd.Dispose();
            con.Close();
        }

        // Cap nhat thong tin sinh vien
        public void UpdateStudent(Student stu)
        {
            string sql = "UPDATE Students SET Fullname = N'" + stu.FullName + "', Address = N'" + stu.Address + "', Note = N'" + stu.Note + "' WHERE ID=" + stu.ID;
            SqlConnection con = new SqlConnection(connectStr);
            SqlCommand cmd = new SqlCommand(sql, con);
            con.Open();
            cmd.ExecuteNonQuery();
            cmd.Dispose();
            con.Close();
        }

        public void DeleteStudent(Student stu)
        {
            string sql = "DELETE Students WHERE ID = " + stu.ID;
            SqlConnection con = new SqlConnection(connectStr);
            SqlCommand cmd = new SqlCommand(sql, con);
            con.Open();
            cmd.ExecuteNonQuery();
            cmd.Dispose();
            con.Close();
        }
    }
}
