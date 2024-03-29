import { useState, useEffect } from 'react'
import { FaSignInAlt } from 'react-icons/fa'
import { useSelector, useDispatch } from 'react-redux'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import { login, reset, loginWithGoogle } from '../features/auth/authSlice'
import Spinner from '../components/Spinner'
import { GoogleLogin } from '@react-oauth/google';
import { LoginSocialGoogle } from 'reactjs-social-login';
function Login() {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  })

  const { email, password } = formData

  const navigate = useNavigate()
  const dispatch = useDispatch()

  const { user, isLoading, isError, isSuccess, message } = useSelector(
    (state) => state.auth
  )

  useEffect(() => {
    if (isError) {
      toast.error(message)
    }

    if (isSuccess || user) {
      navigate('/')
    }

    dispatch(reset())
  }, [user, isError, isSuccess, message, navigate, dispatch])

  const onChange = (e) => {
    setFormData((prevState) => ({
      ...prevState,
      [e.target.name]: e.target.value,
    }))
  }

  const onSubmit = (e) => {
    e.preventDefault()

    const userData = {
      email,
      password,
    }

    dispatch(login(userData))
  }
  const googleSuccess = async (res) => {
    try {
      console.log(res);
      const access_token = res?.access_token;
      dispatch(loginWithGoogle(access_token));
    } catch (error) {
      console.log(error);
    }
  };
  const googleError = () => alert('Google Sign In was unsuccessful. Try again later');
  if (isLoading) {
    return <Spinner />
  }

  return (
    <>
      <section className='heading'>
        <h1>
          <FaSignInAlt /> Login
        </h1>
        <p>Login and start setting goals</p>
      </section>

      <section className='form'>
        <form onSubmit={onSubmit}>
          <div className='form-group'>
            <input
              type='email'
              className='form-control'
              id='email'
              name='email'
              value={email}
              placeholder='Enter your email'
              onChange={onChange}
            />
          </div>
          <div className='form-group'>
            <input
              type='password'
              className='form-control'
              id='password'
              name='password'
              value={password}
              placeholder='Enter password'
              onChange={onChange}
            />
          </div>

          <div className='form-group'>
            <button type='submit' className='btn btn-block'>
              Submit
            </button>
          </div>
        </form>
        {/* <GoogleLogin
          shape="rectangular"
          theme='filled_blue'
          text='Sign up With Google'
          onSuccess={credentialResponse => {
            googleSuccess(credentialResponse);
          }}
          onError={() => {
            googleError();
          }}
        /> */}
        <LoginSocialGoogle
          client_id="client_id"
          onResolve={({ data }) => {
            console.log(data, "data");
            googleSuccess(data);
          }}
          onReject={(err) => {
            console.log("error", err);
          }}
        >
         <button className='btn btn-block'>Google Login</button>
        </LoginSocialGoogle>
      </section>
    </>
  )
}

export default Login
