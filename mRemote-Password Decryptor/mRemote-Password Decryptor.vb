Imports System.Text
Imports System.Security.Cryptography
Imports System.IO

Public Class Form1

    Private Sub btnDecrypt_Click(sender As Object, e As EventArgs) Handles btnDecrypt.Click
        ''Get the md5 hash of mR3m and convert it into byte values: \xc8\xa3\x9d\xe2\xa5\x47\x66\xa0\xda\x87\x5f\x79\xaa\xf1\xaa\x8c

        'setup the DataGridView
        init_Columns_In_DataGridview()

        'xml Document Object
        Dim doc As XDocument

        'Load the textbox
        If TextBox2.Text.Length > 1 Then
            Try
                doc = XDocument.Load(TextBox2.Text)
            Catch ex As Exception
                Return
            End Try

        Else
            'Alert the user
            MsgBox("Please Pick a File Name", MsgBoxStyle.Exclamation, "Attention")
            Return
        End If

        'select the nodes
        Dim nodes = From n In doc.Descendants("Node")
            Select n

        'loop through the nodes
        For Each _node In nodes
            Dim Name As String = _node.Attribute("Name").Value
            Dim Username As String = _node.Attribute("Username").Value
            Dim Domain As String = _node.Attribute("Domain").Value
            Dim Password As String = _node.Attribute("Password").Value
            Dim Hostname As String = _node.Attribute("Hostname").Value
            Dim Protocol As String = _node.Attribute("Protocol").Value
            Dim Port As String = _node.Attribute("Port").Value


            Dim info1 As String = ""
            If Username.Length > 1 Or Password.Length > 1 Then
                Dim md5_data = Md5FromString("mR3m")
                'lblMD5.Text = md5_data
                Dim TheKey As Byte() = md5_data
                Dim pwd_data As String = Password
                'base64 decode the saved password data
                Dim data As Byte() = System.Convert.FromBase64String(Password)
                'Take the first 16 bytes of the decoded data and set that as you Initialization vector(IV)
                Dim iv(15) As Byte
                Array.Copy(data, iv, 16)
                'Take last 16 Bytes
                Dim ec(15) As Byte
                Array.Copy(data, 16, ec, 0, 16)
                ' Dim info As String = RijndealDecrypt(ec, TheKey, iv)
                info1 = EncryptOrDecryptFile(ec, TheKey, iv)
                ' Dim base64_Decoded As String = DecodeBase64()



                Dim Decrypted As String = info1


                Dim row As String() = New String() {Name, Username, Domain, Password, Decrypted, Hostname, Protocol, Port}
                DataGridView1.Rows.Add(row)
            End If


        Next





    End Sub

    Public Function Md5FromString(ByVal Source As String)
        Dim Bytes() As Byte
        Dim sb As New StringBuilder()

        'Check for empty string.
        If String.IsNullOrEmpty(Source) Then
            Throw New ArgumentNullException
        End If

        'Get md5 hash
        Bytes = MD5.Create().ComputeHash(Encoding.Default.GetBytes(Source))



        'Return md5 hash.
        Return Bytes

    End Function

    Private Shared Function RijndealDecrypt(strTxt As Byte(), decryptKey As String, IV As Byte()) As String
        Try
            Dim rm = New RijndaelManaged()
            rm.BlockSize = 128
            rm.IV = IV
            rm.KeySize = 128
            rm.Key = New SHA256Managed().ComputeHash(Encoding.UTF8.GetBytes(decryptKey))
            Dim inputByteArray As Byte() = strTxt
            Dim ms = New MemoryStream()
            Dim cs = New CryptoStream(ms, rm.CreateDecryptor(), CryptoStreamMode.Write)
            cs.Write(inputByteArray, 0, inputByteArray.Length)
            cs.FlushFinalBlock()
            Return Encoding.UTF8.GetString(ms.ToArray())
        Catch
            ' Return Nothing
        End Try
    End Function

    Private Function EncryptOrDecryptFile(ByVal byteDataToBeDecrypted() As Byte, _
                                 ByVal bytKey() As Byte, _
                                 ByVal bytIV() As Byte) As String


        'Declare your CryptoServiceProvider.
        Dim cspRijndael As New System.Security.Cryptography.RijndaelManaged

        'Memory Stream
        Dim mStream As New MemoryStream(byteDataToBeDecrypted, 0, byteDataToBeDecrypted.Length) ' instead of writing the decrypted text
        Dim aes As New RijndaelManaged()
        Dim cs As New CryptoStream(mStream, aes.CreateDecryptor(bytKey, bytIV), CryptoStreamMode.Read)

        'Stream Reader for the cryptostream
        Dim sr As New StreamReader(cs)
        'return the data
        Return sr.ReadToEnd()



    End Function

    Private Sub btnBrowse_Click(sender As Object, e As EventArgs) Handles btnBrowse.Click
        OpenFileDialog1.FileName = "mRemoteConfig.xml"
        OpenFileDialog1.ShowDialog()
        TextBox2.Text = OpenFileDialog1.FileName
    End Sub

    Private Sub init_Columns_In_DataGridview()
        DataGridView1.ColumnCount = 8
        DataGridView1.Columns(0).Name = "Name"
        DataGridView1.Columns(1).Name = "Username"
        DataGridView1.Columns(2).Name = "Domain"
        DataGridView1.Columns(3).Name = "Password"
        DataGridView1.Columns(4).Name = "DecryptPassword"
        DataGridView1.Columns(5).Name = "Hostname"
        DataGridView1.Columns(6).Name = "Protocol"
        DataGridView1.Columns(7).Name = "Port"
    End Sub
 
    Private Sub ExitToolStripMenuItem_Click(sender As Object, e As EventArgs) Handles ExitToolStripMenuItem.Click
        Me.Close()
    End Sub

    Private Sub AboutToolStripMenuItem_Click(sender As Object, e As EventArgs) Handles AboutToolStripMenuItem.Click
        About.Show()
    End Sub

    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load

    End Sub



    Public Shared Function Decrypt(ByVal ciphertextBase64 As String, ByVal password As String) As String
        Dim str As String
        Dim plaintext As String
        Dim flag As Boolean = False
        If (String.IsNullOrEmpty(ciphertextBase64) Or String.IsNullOrEmpty(password)) Then
            Return ciphertextBase64
        End If
        Try
            Using rijndaelManaged As System.Security.Cryptography.RijndaelManaged = New System.Security.Cryptography.RijndaelManaged()
                Using md5 As MD5CryptoServiceProvider = New MD5CryptoServiceProvider()
                    Dim key As Byte() = md5.ComputeHash(Encoding.UTF8.GetBytes(password))
                    rijndaelManaged.Key = key
                End Using
                Using memoryStream As System.IO.MemoryStream = New System.IO.MemoryStream(Convert.FromBase64String(ciphertextBase64))
                    Dim iv(15) As Byte
                    memoryStream.Read(iv, 0, 16)
                    rijndaelManaged.IV = iv
                    Using cryptoStream As System.Security.Cryptography.CryptoStream = New System.Security.Cryptography.CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Read)
                        Using streamReader As System.IO.StreamReader = New System.IO.StreamReader(cryptoStream, Encoding.UTF8, True)
                            plaintext = streamReader.ReadToEnd()
                        End Using
                        rijndaelManaged.Clear()
                    End Using
                End Using
            End Using
            str = plaintext
        Catch exception As System.Exception
            ' ProjectData.SetProjectError(exception)
            Dim ex As System.Exception = exception
            If (Not TypeOf ex Is CryptographicException) Then
                '  Runtime.MessageCollector.AddMessage(MessageClass.ErrorMsg, String.Format(Language.strErrorDecryptionFailed, ex.Message), False)
            End If
            ' ProjectData.ClearProjectError()
            flag = True
        End Try
        If (Not flag) Then
            Return str
        End If
        flag = False
        Return ciphertextBase64
    End Function


End Class
